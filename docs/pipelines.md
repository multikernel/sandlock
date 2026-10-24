# Pipelines and COW Fork

Sandboxes compose. A pipeline chains independently confined stages over
kernel pipes; a COW fork clones one initialized process into many
sandboxed workers and reduces their output through a separate sandbox.

## Pipeline

Chain sandboxed stages with the `|` operator; each stage has its own
independent sandbox config. Data flows through kernel pipes.

```python
from sandlock import Sandbox

trusted = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc", "/opt/data"])
restricted = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc"])

# Reader can access data, processor cannot
result = (
    trusted.cmd(["cat", "/opt/data/secret.csv"])
    | restricted.cmd(["tr", "a-z", "A-Z"])
).run()
assert b"SECRET" in result.stdout
```

**XOA pattern** (Execute-Only Agents): planner generates code,
executor runs it with data access but no network:

```python
planner = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc"])
executor = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc", "/data"])

result = (
    planner.cmd(["python3", "-c", "print('cat /data/input.txt')"])
    | executor.cmd(["sh"])
).run()
```

The same composition is available in Rust through `Stage`:

```rust
use sandlock_core::{Sandbox, Stage};

let producer = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/bin")
    .build()?;
let consumer = producer.clone();
let result = (
    Stage::new(&producer, &["echo", "hello"])
    | Stage::new(&consumer, &["tr", "a-z", "A-Z"])
).run(None).await?;
```

## COW Fork and Map-Reduce

Initialize expensive state once, then fork COW clones that share memory.
Each clone uses raw `fork(2)` with shared copy-on-write pages. 1000
clones in ~530ms, ~1,900 forks/sec.

Each clone's stdout is captured via its own pipe. `reduce()` reads all
pipes and feeds combined output to a reducer's stdin: fully pipe-based
data flow with no temp files.

```python
from sandlock import Sandbox

def init():
    global model, data
    model = load_model()          # 2 GB, loaded once
    data = preprocess_dataset()

def work(clone_id):
    shard = data[clone_id::4]
    print(sum(shard))             # stdout → per-clone pipe

# Map: fork 4 clones with a separate sandbox config
mapper = Sandbox(
    fs_readable=["/usr", "/lib", "/bin", "/etc", "/data"],
    init_fn=init,
    work_fn=work,
)
clones = mapper.fork(4)

# Reduce: pipe clone outputs to reducer stdin
reducer = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc"])
result = reducer.reduce(
    ["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
    clones,
)
print(result.stdout)  # b"total\n"
```

```rust
let mut mapper = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/bin").fs_read("/etc")
    .fs_read("/data")
    .name("mapper")
    .init_fn(|| { load_data(); })
    .work_fn(|id| { println!("{}", compute(id)); })
    .build()?;
let mut clones = mapper.fork(4).await?;

let reducer = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/bin").fs_read("/etc")
    .name("reducer")
    .build()?;
let result = reducer.reduce(
    &["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
    &mut clones,
).await?;
```

Map and reduce run in separate sandboxes with independent configs:
the mapper has data access, the reducer doesn't. Each clone inherits
Landlock + seccomp confinement. The work function receives the clone id
(`0..N-1`) as its argument.
