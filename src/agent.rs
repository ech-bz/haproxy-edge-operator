use crate::{
    error::{OperatorError, Result},
    support::components::ResourceId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{SocketAddr, TcpListener},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
    time::{sleep, timeout},
};

pub(crate) struct Agent {
    pub(crate) bundle: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) haproxy: String,
}
impl Agent {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn bundle(&self) -> Result<(String, BTreeMap<String, Vec<u8>>)> {
        let path = &self.bundle;
        let snapshot = fs::read_link(path.join("..data"))
            .map(|target| path.join(target))
            .unwrap_or_else(|_| path.into());
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(&snapshot).map_err(|error| {
            OperatorError::Config(format!(
                "cannot read HAProxy bundle {}: {error}",
                snapshot.display()
            ))
        })? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') && entry.file_type()?.is_file() {
                files.insert(name, fs::read(entry.path())?);
            }
        }
        if !files.contains_key("haproxy.cfg") || !files.contains_key("crt-list") {
            return Err(OperatorError::Config("incomplete HAProxy bundle".into()));
        }
        Ok((
            ResourceId::new(serde_json::to_vec(&files)?).to_string(),
            files,
        ))
    }

    async fn master(&self, command: &str) -> Result<String> {
        timeout(Duration::from_secs(10), async {
            let path = self.state.join("master.sock");
            let mut socket = UnixStream::connect(&path).await.map_err(|error| {
                OperatorError::Config(format!(
                    "cannot connect to HAProxy master socket {}: {error}",
                    path.display()
                ))
            })?;
            socket.write_all(format!("{command}\n").as_bytes()).await?;
            socket.shutdown().await?;
            let mut response = String::new();
            socket.read_to_string(&mut response).await?;
            Ok(response)
        })
        .await
        .map_err(|_| OperatorError::Config("HAProxy master command timed out".into()))?
    }

    pub(crate) async fn running(&self) -> Result<()> {
        let processes = self.master("show proc").await?;
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

    pub(crate) async fn run(&self) -> Result<()> {
        let switch = |target: &Path| -> Result<()> {
            let state = &self.state;
            let temporary = state.join("next");
            if temporary.exists() || temporary.is_symlink() {
                fs::remove_file(&temporary)?;
            }
            symlink(target, &temporary)?;
            fs::rename(temporary, state.join("current"))?;
            Ok(())
        };
        let listeners = |config: &str| -> Result<BTreeSet<SocketAddr>> {
            config
                .lines()
                .filter_map(|line| line.trim().strip_prefix("bind "))
                .map(|line| {
                    line.split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .parse()
                        .map_err(|_| {
                            OperatorError::Config("unsupported HAProxy bind address".into())
                        })
                })
                .collect()
        };

        fs::create_dir_all(&self.state)?;
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut child: Option<Child> = None;
        let mut applied = String::new();
        loop {
            if let Some(child) = child.as_mut()
                && let Some(status) = child.try_wait()?
            {
                return Err(OperatorError::Config(format!("HAProxy exited: {status}")));
            }
            match self.bundle() {
                Ok((revision, files)) if revision != applied => {
                    let result: Result<()> = async {
                        let child = &mut child;
                        let revision = revision.as_str();
                        let generation = self.state.join(format!("generation-{revision}"));
                        fs::create_dir_all(&generation)?;
                        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700))?;
                        for (name, contents) in files {
                            let contents = if name == "haproxy.cfg" || name == "crt-list" {
                                String::from_utf8(contents)
                                    .map_err(|_| {
                                        OperatorError::Config(
                                            "invalid configuration encoding".into(),
                                        )
                                    })?
                                    .replace("@BUNDLE@", &generation.to_string_lossy())
                                    .into_bytes()
                            } else {
                                contents
                            };
                            fs::write(generation.join(name), contents)?;
                        }
                        let output = Command::new(&self.haproxy)
                            .arg("-c")
                            .arg("-f")
                            .arg(generation.join("haproxy.cfg"))
                            .output()
                            .await
                            .map_err(|error| {
                                OperatorError::Config(format!(
                                    "cannot run {}: {error}",
                                    self.haproxy
                                ))
                            })?;
                        if !output.status.success() {
                            return Err(OperatorError::Config(format!(
                                "HAProxy rejected bundle: {}",
                                String::from_utf8_lossy(&output.stderr)
                            )));
                        }
                        let previous = fs::read_link(self.state.join("current")).ok();
                        let previous_listeners = if child.is_some() {
                            listeners(&fs::read_to_string(self.state.join("current/haproxy.cfg"))?)?
                        } else {
                            BTreeSet::new()
                        };
                        for address in
                            listeners(&fs::read_to_string(generation.join("haproxy.cfg"))?)?
                        {
                            drop(TcpListener::bind((address.ip(), 0)).map_err(|error| {
                                OperatorError::Config(format!(
                                    "cannot bind local IP {}: {error}",
                                    address.ip()
                                ))
                            })?);
                            if !previous_listeners.contains(&address) {
                                drop(TcpListener::bind(address).map_err(|error| {
                                    OperatorError::Config(format!(
                                        "cannot bind listener {address}: {error}"
                                    ))
                                })?);
                            }
                        }
                        switch(&generation)?;
                        let result = async {
                            if child.is_some() {
                                let response = self.master("reload").await?;
                                if response.lines().any(|line| line == "Success=1") {
                                    Ok(())
                                } else {
                                    Err(OperatorError::Config(format!(
                                        "HAProxy reload failed: {response}"
                                    )))
                                }
                            } else {
                                *child = Some(
                                    Command::new(&self.haproxy)
                                        .args(["-W", "-db", "-S"])
                                        .arg(self.state.join("master.sock"))
                                        .arg("-f")
                                        .arg(self.state.join("current/haproxy.cfg"))
                                        .kill_on_drop(true)
                                        .spawn()?,
                                );
                                timeout(Duration::from_secs(10), async {
                                    while self.running().await.is_err() {
                                        if child.as_mut().unwrap().try_wait()?.is_some() {
                                            return Err(OperatorError::Config(
                                                "HAProxy exited during startup".into(),
                                            ));
                                        }
                                        sleep(Duration::from_millis(50)).await;
                                    }
                                    Ok(())
                                })
                                .await
                                .map_err(|_| {
                                    OperatorError::Config("HAProxy startup timed out".into())
                                })?
                            }
                        }
                        .await;
                        if let Err(error) = result {
                            if let Some(previous) = previous {
                                switch(&previous)?;
                                let recovery = self.master("reload").await?;
                                if !recovery.lines().any(|line| line == "Success=1") {
                                    return Err(OperatorError::Config(format!(
                                        "HAProxy rollback failed after {error}: {recovery}"
                                    )));
                                }
                            }
                            return Err(error);
                        }
                        fs::write(self.state.join("applied"), revision)?;
                        for entry in fs::read_dir(&self.state)? {
                            let entry = entry?;
                            if entry.file_type()?.is_dir()
                                && entry
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with("generation-")
                                && entry.path() != generation
                                && Some(entry.path()).as_ref() != previous.as_ref()
                            {
                                fs::remove_dir_all(entry.path())?;
                            }
                        }
                        tracing::info!(%revision, "HAProxy configuration applied");
                        Ok(())
                    }
                    .await;
                    match result {
                        Ok(()) => applied = revision,
                        Err(error) => {
                            tracing::warn!(%error, "keeping last working HAProxy configuration")
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "waiting for HAProxy bundle"),
                _ => {}
            }
            tokio::select! {
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
                _ = sleep(Duration::from_secs(2)) => {}
            }
        }
        if let Some(mut child) = child {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGUSR1);
                }
            }
            if timeout(Duration::from_secs(25), child.wait())
                .await
                .is_err()
            {
                child.kill().await?;
            }
        }
        Ok(())
    }
}
