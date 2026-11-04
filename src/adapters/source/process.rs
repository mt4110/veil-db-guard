//! One bounded process group, scrubbed environment and no output in errors.
use super::gce_host::SourceError;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;

pub(super) struct ProcessGroup(Option<u32>);
impl ProcessGroup {
    pub(super) fn new(id: Option<u32>) -> Self {
        Self(id)
    }
    pub(super) fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(id) = self
            .0
            .take()
            .and_then(|n| i32::try_from(n).ok())
            .filter(|id| *id > 0)
        {
            unsafe {
                libc::kill(-id, libc::SIGKILL);
            }
        }
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}
async fn read<R: AsyncRead + Unpin>(stream: R, limit: usize) -> Result<Vec<u8>, SourceError> {
    let mut out = vec![];
    stream
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .await
        .map_err(|_| SourceError::Unavailable)?;
    if out.len() > limit {
        return Err(SourceError::Limit);
    }
    Ok(out)
}
pub(super) async fn run(
    program: &Path,
    args: &[String],
    input: &[u8],
    max_output: usize,
    seconds: u64,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, SourceError> {
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| SourceError::Unavailable)?;
    let group = ProcessGroup(child.id());
    let mut stdin = child.stdin.take().ok_or(SourceError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(SourceError::Unavailable)?;
    let stderr = child.stderr.take().ok_or(SourceError::Unavailable)?;
    let work = async {
        let (status, output, _, ()) = tokio::try_join!(
            async { child.wait().await.map_err(|_| SourceError::Unavailable) },
            read(stdout, max_output),
            read(stderr, 8192),
            async {
                stdin
                    .write_all(input)
                    .await
                    .map_err(|_| SourceError::Unavailable)?;
                stdin.shutdown().await.map_err(|_| SourceError::Unavailable)
            }
        )?;
        if !status.success() {
            return Err(SourceError::Unavailable);
        }
        Ok(output)
    };
    let result = tokio::select! {biased;_=cancel.cancelled()=>Err(SourceError::Cancelled),
    value=tokio::time::timeout(Duration::from_secs(seconds),work)=>value.unwrap_or(Err(SourceError::TimedOut))};
    drop(group);
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn helper(root: &std::path::Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("helper");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[tokio::test]
    async fn child_environment_does_not_inherit_credentials_proxy_or_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = helper(
            dir.path(),
            "printf '%s:%s:%s' \"$SSH_AUTH_SOCK\" \"$HTTPS_PROXY\" \"$GOOGLE_APPLICATION_CREDENTIALS\"",
        );
        assert_eq!(
            run(&path, &[], &[], 64, 2, &CancellationToken::new())
                .await
                .unwrap(),
            b"::"
        );
    }
    #[tokio::test]
    async fn stdout_and_stderr_are_bounded_and_errors_never_echo_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = helper(dir.path(), "printf SENSITIVE-CAPTURE; exit 1");
        let error = run(&path, &[], &[], 64, 2, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(!format!("{error:?}").contains("SENSITIVE"));
        let path = helper(dir.path(), "while :; do printf flood; done");
        assert_eq!(
            run(&path, &[], &[], 64, 2, &CancellationToken::new()).await,
            Err(SourceError::Limit)
        );
        let path = helper(dir.path(), "while :; do printf flood >&2; done");
        assert_eq!(
            run(&path, &[], &[], 64, 2, &CancellationToken::new()).await,
            Err(SourceError::Limit)
        );
    }
    #[tokio::test]
    async fn cancelled_and_timed_out_process_groups_are_stopped_and_parent_reaped() {
        for cancel_case in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let pid = dir.path().join("child-pid");
            let path = helper(
                dir.path(),
                "/bin/sleep 30 &\nchild=$!\nprintf '%s' \"$child\" > \"$1\"\nwait",
            );
            let cancel = CancellationToken::new();
            let c = cancel.clone();
            let signal = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if cancel_case {
                    c.cancel();
                }
            });
            let result = run(&path, &[pid.to_str().unwrap().into()], &[], 64, 1, &cancel).await;
            signal.await.unwrap();
            assert_eq!(
                result,
                Err(if cancel_case {
                    SourceError::Cancelled
                } else {
                    SourceError::TimedOut
                })
            );
            let child = std::fs::read_to_string(pid).unwrap();
            for _ in 0..30 {
                let output = std::process::Command::new("/bin/ps")
                    .args(["-p", child.trim(), "-o", "stat="])
                    .output()
                    .unwrap();
                if !output.status.success()
                    || String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .starts_with('Z')
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let output = std::process::Command::new("/bin/ps")
                .args(["-p", child.trim(), "-o", "stat="])
                .output()
                .unwrap();
            assert!(
                !output.status.success()
                    || String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .starts_with('Z')
            );
        }
    }
}
