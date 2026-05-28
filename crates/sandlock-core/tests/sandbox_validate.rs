use sandlock_core::sandbox::{FsIsolation, Sandbox};

#[test]
fn validate_branchfs_without_workdir_fails() {
    let p = Sandbox::builder()
        .fs_isolation(FsIsolation::BranchFs)
        .build_unchecked()
        .unwrap();
    let err = p.validate().unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("workdir"));
}

#[test]
fn validate_none_without_workdir_succeeds() {
    let p = Sandbox::builder()
        .fs_isolation(FsIsolation::None)
        .build_unchecked()
        .unwrap();
    assert!(p.validate().is_ok());
}
