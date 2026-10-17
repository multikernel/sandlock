//! Images held by a local Docker daemon, fetched through its image-save
//! API (`GET /images/{name}/get`), which Docker 25+ answers with an OCI
//! image layout archive.

use std::path::Path;

use bollard::Docker;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use super::{blocking, oci, unpack, Cache, Image};
use crate::error::{SandboxRuntimeError, SandlockError};

pub(super) async fn pull(cache: &Cache, name: &str) -> Result<Image, SandlockError> {
    let docker = connect().await?;
    let id = docker
        .inspect_image(name)
        .await
        .map_err(|e| {
            docker_error(format!(
                "image not found in local Docker storage: {name} ({e})"
            ))
        })?
        .id
        .ok_or_else(|| docker_error(format!("Docker returned no id for image {name}")))?;
    // Docker's image id is a content digest, so it keys the cache without
    // exporting anything on a hit.
    let key = oci::digest_hex(&id)?.to_string();
    if let Some(image) = cache.lookup(&key) {
        return Ok(image);
    }

    let archive = cache.temp_path(".tar")?;
    let saved = save(&docker, name, &archive).await;
    let result = match saved {
        Ok(()) => {
            let (cache, archive) = (cache.clone(), archive.clone());
            blocking(move || {
                let blobs = oci::LayoutArchive::open(&archive).map_err(|e| {
                    docker_error(format!("{e} (image save needs Docker 25 or newer)"))
                })?;
                let manifest = oci::resolve(&blobs, None)?;
                cache.get_or_build(&key, |rootfs| unpack(&blobs, &manifest, rootfs))
            })
            .await
        }
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_file(&archive);
    result
}

/// Connect to the local Docker daemon and verify it is actually reachable,
/// so `--image` fails up front rather than mid-setup.
async fn connect() -> Result<Docker, SandlockError> {
    let unreachable = |e: bollard::errors::Error| {
        docker_error(format!(
            "cannot reach the Docker daemon (is dockerd running and the socket accessible?): {e}"
        ))
    };
    let docker = Docker::connect_with_local_defaults().map_err(unreachable)?;
    docker.ping().await.map_err(unreachable)?;
    Ok(docker)
}

/// Stream the image-save archive to disk rather than holding an image in memory.
async fn save(docker: &Docker, name: &str, dest: &Path) -> Result<(), SandlockError> {
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(SandboxRuntimeError::Io)?;
    let mut stream = docker.export_image(name);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| docker_error(format!("image save failed: {e}")))?;
        file.write_all(&chunk)
            .await
            .map_err(SandboxRuntimeError::Io)?;
    }
    file.flush().await.map_err(SandboxRuntimeError::Io)?;
    Ok(())
}

fn docker_error(msg: String) -> SandlockError {
    SandboxRuntimeError::Child(format!("docker-daemon: {msg}")).into()
}
