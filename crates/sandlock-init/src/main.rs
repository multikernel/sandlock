//! sandlock-init: confined PID-1 that fork-execs the workload and exec'd
//! commands on request from the daemon over CONTROL_FD. Filled in Task 3.
#[path = "proto.rs"]
mod proto;

fn main() {
    // Skeleton: real loop arrives in Task 3.
    std::process::exit(0);
}
