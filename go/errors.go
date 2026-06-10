package sandlock

import "errors"

// ErrInvalidString is returned when a string passed to the SDK contains an
// interior NUL byte, which cannot cross the C ABI boundary intact.
var ErrInvalidString = errors.New("sandlock: string contains NUL byte")

// ErrNotRunning is returned by *Process lifecycle methods when no process is
// currently running in the handle.
var ErrNotRunning = errors.New("sandlock: process is not running")
