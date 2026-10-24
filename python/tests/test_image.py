# SPDX-License-Identifier: Apache-2.0
"""Container images: pull_image() and Sandbox(image=...)."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from _rootfs_helper import rootfs_helper
from sandlock import Image, ImageConfig, Sandbox, SandlockError, pull_image


def _write_helper_image(layout: Path) -> None:
    """An OCI layout holding the static rootfs-helper, with a config that
    sets env and a working directory the layer does not contain."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for d in ("usr", "usr/bin", "proc", "dev", "tmp"):
            info = tarfile.TarInfo(d)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(info)
        data = rootfs_helper().read_bytes()
        info = tarfile.TarInfo("usr/bin/rootfs-helper")
        info.mode, info.size = 0o755, len(data)
        tar.addfile(info, io.BytesIO(data))

    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def blob(media_type: str, data: bytes) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return {"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(data)}

    config = json.dumps({"config": {
        "Env": ["PATH=/usr/bin", "GREETING=from-image"],
        "WorkingDir": "/work/here",
        "Cmd": ["rootfs-helper", "pwd"],
    }}).encode()
    manifest = json.dumps({
        "schemaVersion": 2,
        "config": blob("application/vnd.oci.image.config.v1+json", config),
        "layers": [blob("application/vnd.oci.image.layer.v1.tar", layer.getvalue())],
    }).encode()
    index = {"schemaVersion": 2, "manifests": [blob("application/vnd.oci.image.manifest.v1+json", manifest)]}
    (layout / "index.json").write_text(json.dumps(index))


def test_pull_image_and_run_in_it(tmp_path):
    layout = tmp_path / "layout"
    _write_helper_image(layout)

    image = pull_image(f"oci:{layout}", cache_dir=tmp_path / "cache")
    assert (Path(image.rootfs) / "usr/bin/rootfs-helper").is_file()
    assert image.config.default_cmd() == ["rootfs-helper", "pwd"]
    assert image.config.working_dir == "/work/here"
    assert "GREETING=from-image" in image.config.env

    result = Sandbox(image=image).run(image.config.default_cmd())
    assert result.success, result.stderr
    assert result.stdout.strip() == b"/work/here"

    result = Sandbox(image=image, cwd="/tmp").run(["rootfs-helper", "pwd"])
    assert result.stdout.strip() == b"/tmp", "an explicit cwd must win over the image's"


def test_image_writes_are_discarded(tmp_path):
    layout = tmp_path / "layout"
    _write_helper_image(layout)
    image = pull_image(f"oci:{layout}", cache_dir=tmp_path / "cache")

    result = Sandbox(image=image, fs_writable=["/tmp"]).run(["rootfs-helper", "write", "/tmp/f", "x"])
    assert result.success, result.stderr
    assert not (Path(image.rootfs) / "tmp/f").exists(), "a run must never change the cached image"

    with pytest.raises(RuntimeError, match="on_error must be abort"):
        Sandbox(image=image, on_error="commit").run(["rootfs-helper", "pwd"])


def test_pull_image_reports_failure(tmp_path):
    with pytest.raises(SandlockError, match="not an OCI image layout"):
        pull_image("oci:/nonexistent/layout", cache_dir=tmp_path)


def test_default_cmd_falls_back_to_shell():
    assert ImageConfig().default_cmd() == ["/bin/sh"]
    assert Image(rootfs="/r").config == ImageConfig()
