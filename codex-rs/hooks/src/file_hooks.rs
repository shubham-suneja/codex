//! File-based hook discovery and execution.
//!
//! Scans `.codex/hooks/` directory for executable scripts matching event names.
//! Scripts receive the hook payload as JSON via stdin.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::types::{Hook, HookPayload, HookResult};

/// Event names that map to hook script filenames.
const EVENT_NAMES: &[&str] = &[
    "after_agent",
    "after_tool_use",
    "before_tool_use",
    "prompt",
    "stop",
    "notification",
    "commit",
    "session_end",
];

/// Discover hook scripts from a directory.
/// Scripts should be named after event types (e.g., `after_agent`, `stop`).
/// They can have any extension or no extension, as long as they're executable.
pub fn discover_hooks(hooks_dir: &Path) -> Vec<(String, Vec<Hook>)> {
    let mut result = Vec::new();

    if !hooks_dir.is_dir() {
        return result;
    }

    for event_name in EVENT_NAMES {
        let mut hooks_for_event = Vec::new();

        // Check for exact match (e.g., `after_agent`)
        let exact_path = hooks_dir.join(event_name);
        if exact_path.is_file() && is_executable(&exact_path) {
            hooks_for_event.push(make_file_hook(event_name, &exact_path));
        }

        // Check for files with extensions (e.g., `after_agent.sh`, `after_agent.py`)
        if let Ok(entries) = std::fs::read_dir(hooks_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() || path == exact_path {
                    continue;
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if stem == *event_name && is_executable(&path) {
                        hooks_for_event.push(make_file_hook(event_name, &path));
                    }
                }
            }
        }

        if !hooks_for_event.is_empty() {
            result.push((event_name.to_string(), hooks_for_event));
        }
    }

    result
}

/// Find the hooks directory. Checks:
/// 1. `$CODEX_HOOKS_DIR` env var
/// 2. `.codex/hooks/` in current directory
/// 3. `~/.codex/hooks/` in home directory
pub fn find_hooks_dir(cwd: &Path) -> Option<PathBuf> {
    // Check env var first
    if let Ok(dir) = std::env::var("CODEX_HOOKS_DIR") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return Some(p);
        }
    }

    // Check .codex/hooks/ in cwd
    let local = cwd.join(".codex").join("hooks");
    if local.is_dir() {
        return Some(local);
    }

    // Check ~/.codex/hooks/
    if let Some(home) = dirs::home_dir() {
        let global = home.join(".codex").join("hooks");
        if global.is_dir() {
            return Some(global);
        }
    }

    None
}

fn make_file_hook(event_name: &str, script_path: &Path) -> Hook {
    let name = format!(
        "file:{}:{}",
        event_name,
        script_path.file_name().unwrap_or_default().to_string_lossy()
    );
    let script_path = script_path.to_path_buf();

    Hook {
        name,
        func: Arc::new(move |payload: &HookPayload| {
            let script_path = script_path.clone();
            Box::pin(async move {
                execute_file_hook(&script_path, payload).await
            })
        }),
    }
}

async fn execute_file_hook(script_path: &Path, payload: &HookPayload) -> HookResult {
    let json = match serde_json::to_string(payload) {
        Ok(j) => j,
        Err(e) => return HookResult::FailedContinue(e.into()),
    };

    let mut command = Command::new(script_path);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("CODEX_HOOK_EVENT", format!("{}", event_type_name(&payload.hook_event)))
        .env("CODEX_HOOK_SESSION_ID", payload.session_id.to_string())
        .env("CODEX_HOOK_CWD", payload.cwd.display().to_string());

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => return HookResult::FailedContinue(e.into()),
    };

    // Write JSON payload to stdin
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(json.as_bytes()).await {
            return HookResult::FailedContinue(Box::new(e));
        }
        drop(stdin);
    }

    match child.wait().await {
        Ok(status) => {
            if status.success() {
                HookResult::Success
            } else {
                let code = status.code().unwrap_or(-1);
                if code == 2 {
                    // Exit code 2 = abort operation
                    HookResult::FailedAbort(
                        std::io::Error::other(format!(
                            "hook script {} exited with code 2 (abort)",
                            script_path.display()
                        ))
                        .into(),
                    )
                } else {
                    HookResult::FailedContinue(
                        std::io::Error::other(format!(
                            "hook script {} exited with code {}",
                            script_path.display(),
                            code
                        ))
                        .into(),
                    )
                }
            }
        }
        Err(e) => HookResult::FailedContinue(e.into()),
    }
}

fn event_type_name(event: &crate::types::HookEvent) -> &'static str {
    use crate::types::HookEvent;
    match event {
        HookEvent::AfterAgent { .. } => "after_agent",
        HookEvent::AfterToolUse { .. } => "after_tool_use",
        HookEvent::BeforeToolUse { .. } => "before_tool_use",
        HookEvent::Prompt { .. } => "prompt",
        HookEvent::Stop { .. } => "stop",
        HookEvent::Notification { .. } => "notification",
        HookEvent::Commit { .. } => "commit",
        HookEvent::SessionEnd { .. } => "session_end",
    }
}

#[cfg(not(windows))]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    // On Windows, check for common script extensions
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e.to_lowercase().as_str(), "bat" | "cmd" | "ps1" | "exe"))
        .unwrap_or(false)
}
