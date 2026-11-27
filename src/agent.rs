use crate::{
    error::{OperatorError, Result},
    support::components::hash,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

pub(crate) struct Settings {
    pub(crate) bundle: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) haproxy: String,
}
impl Settings {
    pub(crate) fn load() -> Self {
        Self {
            bundle: std::env::var_os("EDGE_BUNDLE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/etc/edge".into()),
            state: std::env::var_os("EDGE_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/run/edge/state".into()),
            haproxy: std::env::var("EDGE_HAPROXY_BIN").unwrap_or_else(|_| "haproxy".into()),
        }
    }
}

pub(crate) fn bundle(path: &Path) -> Result<(String, BTreeMap<String, Vec<u8>>)> {
    let snapshot = fs::read_link(path.join("..data"))
        .map(|target| path.join(target))
        .unwrap_or_else(|_| path.into());
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(snapshot)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') && entry.file_type()?.is_file() {
            files.insert(name, fs::read(entry.path())?);
        }
    }
    if !files.contains_key("haproxy.cfg") || !files.contains_key("crt-list") {
        return Err(OperatorError::Config("incomplete HAProxy bundle".into()));
    }
    Ok((hash(serde_json::to_vec(&files)?), files))
}

pub(crate) async fn master(state: &Path, command: &str) -> Result<String> {
    timeout(Duration::from_secs(10), async {
        let mut socket = UnixStream::connect(state.join("master.sock")).await?;
        socket.write_all(format!("{command}\n").as_bytes()).await?;
        socket.shutdown().await?;
        let mut response = String::new();
        socket.read_to_string(&mut response).await?;
        Ok(response)
    })
    .await
    .map_err(|_| OperatorError::Config("HAProxy master command timed out".into()))?
}

pub(crate) async fn running(state: &Path) -> Result<()> {
    let processes = master(state, "show proc").await?;
    if !processes
        .lines()
        .take_while(|line| !line.starts_with("# old workers"))
        .any(|line| line.split_whitespace().nth(1) == Some("worker"))
    {
        return Err(OperatorError::Config(
            "HAProxy has no current worker".into(),
        ));
    }
    Ok(())
}

pub(crate) fn switch(state: &Path, target: &Path) -> Result<()> {
    let temporary = state.join("next");
    if temporary.exists() || temporary.is_symlink() {
        fs::remove_file(&temporary)?;
    }
    symlink(target, &temporary)?;
    fs::rename(temporary, state.join("current"))?;
    Ok(())
}

pub(crate) fn listeners(config: &str) -> Result<BTreeSet<SocketAddr>> {
    config
        .lines()
        .filter_map(|line| line.trim().strip_prefix("bind "))
        .map(|line| {
            line.split_whitespace()
                .next()
                .unwrap_or_default()
                .parse()
                .map_err(|_| OperatorError::Config("unsupported HAProxy bind address".into()))
        })
        .collect()
}
