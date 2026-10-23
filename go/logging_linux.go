//go:build linux

package sandlock

/*
#include "sandlock.h"

extern void goLogCallback(uint32_t level, char *message, void *user_data);
*/
import "C"

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	nativeLogger atomic.Pointer[slog.Logger]
	setLoggerMu  sync.Mutex
)

const levelTrace = slog.LevelDebug - 4

var nativeLevels = []struct {
	native C.uint32_t
	level  slog.Level
}{
	{C.SANDLOCK_LOG_TRACE, levelTrace},
	{C.SANDLOCK_LOG_DEBUG, slog.LevelDebug},
	{C.SANDLOCK_LOG_INFO, slog.LevelInfo},
	{C.SANDLOCK_LOG_WARN, slog.LevelWarn},
	{C.SANDLOCK_LOG_ERROR, slog.LevelError},
}

//export goLogCallback
func goLogCallback(level C.uint32_t, message *C.char, _ unsafe.Pointer) {
	l := nativeLogger.Load()
	if l == nil {
		return
	}
	lvl := slog.LevelError
	for _, n := range nativeLevels {
		if n.native == level {
			lvl = n.level
		}
	}
	l.Log(context.Background(), lvl, C.GoString(message))
}

// SetLogger sends the native library's diagnostics to l, or discards them
// when l is nil, the default. Records arrive asynchronously and are dropped
// while l falls behind; the levels l does not enable are never produced.
func SetLogger(l *slog.Logger) error {
	setLoggerMu.Lock()
	defer setLoggerMu.Unlock()
	var rc C.int
	if l == nil {
		rc = C.sandlock_set_logger(nil, 0, nil)
		nativeLogger.Store(nil)
	} else {
		nativeLogger.Store(l)
		rc = C.sandlock_set_logger((*[0]byte)(C.goLogCallback), maxNativeLevel(l), nil)
	}
	if rc < 0 {
		return syscall.Errno(-rc)
	}
	return nil
}

func maxNativeLevel(l *slog.Logger) C.uint32_t {
	for _, n := range nativeLevels {
		if l.Enabled(context.Background(), n.level) {
			return n.native
		}
	}
	return 0
}
