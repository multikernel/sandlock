"""Build sandlock: compile Rust FFI library and install Python package."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop


RUST_DIR = Path(__file__).parent.parent  # project root (contains Cargo.toml)
LIB_NAME = "libsandlock_ffi.so"


def build_rust():
    """Build the Rust FFI shared library in release mode."""
    if not RUST_DIR.exists():
        raise RuntimeError(f"Rust source not found at {RUST_DIR}")

    subprocess.check_call(
        ["cargo", "build", "--release", "-p", "sandlock-ffi"],
        cwd=RUST_DIR,
    )

    lib_path = RUST_DIR / "target" / "release" / LIB_NAME
    if not lib_path.exists():
        raise RuntimeError(f"Rust build did not produce {lib_path}")
    return lib_path


def copy_lib_to_package(lib_path: Path):
    """Copy the shared library into the Python package directory."""
    dest = Path(__file__).parent / "src" / "sandlock" / LIB_NAME
    shutil.copy2(lib_path, dest)
    return dest


class BuildPyWithRust(build_py):
    """Build Rust library before building Python package."""

    def run(self):
        lib_path = build_rust()
        copy_lib_to_package(lib_path)
        super().run()


class DevelopWithRust(develop):
    """Build Rust library for editable installs (pip install -e .)."""

    def run(self):
        lib_path = build_rust()
        copy_lib_to_package(lib_path)
        super().run()


setup(
    cmdclass={
        "build_py": BuildPyWithRust,
        "develop": DevelopWithRust,
    },
)
