# sandlock build helpers.
#
# The Go SDK links the native libsandlock_ffi via cgo. Released builds discover
# it through pkg-config; `install-go-lib` lays down the three files pkg-config
# needs (the shared library, the cbindgen header, and sandlock.pc).

PREFIX ?= /usr/local
DESTDIR ?=
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

LIBDIR := $(DESTDIR)$(PREFIX)/lib
INCLUDEDIR := $(DESTDIR)$(PREFIX)/include
PCDIR := $(LIBDIR)/pkgconfig

.PHONY: ffi install-go-lib uninstall-go-lib

# Build the native FFI shared library.
ffi:
	cargo build --release -p sandlock-ffi

# Install the native library, header, and pkg-config file so that
# `pkg-config --cflags --libs sandlock` resolves and the Go SDK builds in its
# default (pkg-config) mode. Honors PREFIX and DESTDIR.
install-go-lib: ffi
	install -Dm755 target/release/libsandlock_ffi.so $(LIBDIR)/libsandlock_ffi.so
	install -Dm644 crates/sandlock-ffi/include/sandlock.h $(INCLUDEDIR)/sandlock.h
	install -d $(PCDIR)
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(VERSION)|g' \
		go/sandlock.pc.in > $(PCDIR)/sandlock.pc

uninstall-go-lib:
	rm -f $(LIBDIR)/libsandlock_ffi.so \
		$(INCLUDEDIR)/sandlock.h \
		$(PCDIR)/sandlock.pc
