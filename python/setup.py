"""Build sandlock: compile Rust FFI library and install Python package."""

import shutil
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop


RUST_DIR = Path(__file__).parent.parent  # project root (contains Cargo.toml)
LIB_NAME = "libsandlock_ffi.so"
BUNDLED_LIB = Path(__file__).parent / "src" / "sandlock" / LIB_NAME


def build_rust():
    """Build the Rust FFI shared library in release mode.

    Returns the path to the built library, or None if the Rust source
    is not available (e.g. installing from sdist on PyPI).
    """
    cargo_toml = RUST_DIR / "Cargo.toml"
    if not cargo_toml.exists():
        # No Rust source — use the pre-bundled .so from the sdist.
        if BUNDLED_LIB.exists():
            return None
        raise RuntimeError(
            "Rust source not found and no pre-built libsandlock_ffi.so bundled. "
            "Install from a wheel or build from the full source tree."
        )

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
    dest = BUNDLED_LIB
    shutil.copy2(lib_path, dest)
    return dest


class BuildPyWithRust(build_py):
    """Build Rust library before building Python package."""

    def run(self):
        lib_path = build_rust()
        if lib_path is not None:
            copy_lib_to_package(lib_path)
        super().run()


class DevelopWithRust(develop):
    """Build Rust library for editable installs (pip install -e .)."""

    def run(self):
        lib_path = build_rust()
        if lib_path is not None:
            copy_lib_to_package(lib_path)
        super().run()


# Read README from project root for PyPI description.
readme_path = RUST_DIR / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    cmdclass={
        "build_py": BuildPyWithRust,
        "develop": DevelopWithRust,
    },
    long_description=long_description,
    long_description_content_type="text/markdown",
)
