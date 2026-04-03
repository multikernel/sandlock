"""Build sandlock: compile Rust FFI library and install Python package."""

from pathlib import Path

from setuptools import setup
from setuptools_rust import Binding, RustExtension

# Read README from project root for PyPI description.
RUST_DIR = Path(__file__).parent.parent
readme_path = RUST_DIR / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    rust_extensions=[
        RustExtension(
            "sandlock.libsandlock_ffi",
            path="../crates/sandlock-ffi/Cargo.toml",
            binding=Binding.NoBinding,
        ),
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
)
