#[path = "integration/test_policy.rs"]
mod test_policy;

#[path = "integration/test_sandbox.rs"]
mod test_sandbox;

#[path = "integration/test_determinism.rs"]
mod test_determinism;

#[path = "integration/test_cow.rs"]
mod test_cow;

#[path = "integration/test_checkpoint.rs"]
mod test_checkpoint;

#[path = "integration/test_procfs.rs"]
mod test_procfs;

#[path = "integration/test_port_remap.rs"]
mod test_port_remap;

#[path = "integration/test_resource.rs"]
mod test_resource;

#[path = "integration/test_seccomp_enforce.rs"]
mod test_seccomp_enforce;

#[path = "integration/test_landlock.rs"]
mod test_landlock;

#[path = "integration/test_pipeline.rs"]
mod test_pipeline;

#[path = "integration/test_network.rs"]
mod test_network;

#[path = "integration/test_policy_fn.rs"]
mod test_policy_fn;

#[path = "integration/test_fork.rs"]
mod test_fork;

#[path = "integration/test_privileged.rs"]
mod test_privileged;
