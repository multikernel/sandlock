fn main() {
    // include/sandlock.h is generated from this crate's #[no_mangle] exports
    // by cbindgen, not produced here: the build does not run cbindgen so a
    // plain `cargo build` needs no extra tooling. Regenerate the header with
    // the command in cbindgen.toml after changing the C ABI; CI checks that the
    // committed header matches a fresh generation.
    // Run `cargo build -p sandlock-ffi` then find the .so in target/release/.
}
