//go:build linux && !sandlock_repo

package sandlock

// Default build mode: resolve the installed libsandlock_ffi and its header
// through pkg-config. Install the native side first (for example with
// `make install-go-lib` from the repository root, or a release tarball that
// provides sandlock.pc, sandlock.h, and libsandlock_ffi.so), so that
// `pkg-config --cflags --libs sandlock` succeeds. To build against an
// uninstalled checkout instead, use `-tags sandlock_repo` (see cgo_repo.go).

// #cgo pkg-config: sandlock
import "C"
