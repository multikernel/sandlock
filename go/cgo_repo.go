//go:build linux && sandlock_repo

package sandlock

// In-tree build mode (opt in with `-tags sandlock_repo`): resolve the header
// and libsandlock_ffi from this checkout's build output, with no install step.
// Build the native library first: `cargo build --release -p sandlock-ffi`.
// This is the mode used by the repository's own CI and local development.

/*
#cgo CFLAGS: -I${SRCDIR}/../crates/sandlock-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -lsandlock_ffi -lpthread -ldl -lm
*/
import "C"
