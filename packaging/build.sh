#!/bin/sh
# Usage: packaging/build.sh <bindir> <version> <goarch> <outdir>
# <bindir> holds a release build's sandlock, sandlock-oci and libsandlock_ffi.so.
set -eu

bindir=$1 version=$2 arch=$3 outdir=$4
root=$(cd "$(dirname "$0")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

cp "$bindir/sandlock" "$bindir/sandlock-oci" "$bindir/libsandlock_ffi.so" "$stage/"
cp "$root/crates/sandlock-ffi/include/sandlock.h" "$root/LICENSE" "$stage/"
for lib in lib lib64; do
	sed -e 's|@PREFIX@|/usr|g' -e "s|@LIBDIR@|\${exec_prefix}/$lib|g" -e "s|@VERSION@|$version|g" \
		"$root/go/sandlock.pc.in" > "$stage/sandlock-$lib.pc"
done

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
cd "$stage"
for fmt in deb rpm; do
	case $fmt in deb) dev=sandlock-dev ;; rpm) dev=sandlock-devel ;; esac
	VERSION=$version ARCH=$arch \
		nfpm package -f "$root/packaging/nfpm.yaml" -p "$fmt" -t "$outdir/"
	NAME=$dev VERSION=$version ARCH=$arch \
		nfpm package -f "$root/packaging/nfpm-dev.yaml" -p "$fmt" -t "$outdir/"
done
