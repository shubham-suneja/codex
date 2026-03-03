# Codex CLI Hooks System

File-based hook scripts that fire on lifecycle events, matching Claude Code's hook pattern for tool monitoring.

## Setup

Create hook scripts in one of these locations (checked in order):

1. `$CODEX_HOOKS_DIR` (env var)
2. `.codex/hooks/` in your project directory
3. `~/.codex/hooks/` in your home directory

Scripts must be **executable** (`chmod +x`) and named after the event type.

## Event Types

| Event | File Name | When It Fires |
|-------|-----------|---------------|
| **Prompt** | `prompt` | Agent starts working on a user prompt |
| **BeforeToolUse** | `before_tool_use` | Before a tool/command is executed |
| **AfterToolUse** | `after_tool_use` | After a tool/command completes |
| **AfterAgent** | `after_agent` | Agent finishes a turn |
| **Stop** | `stop` | Agent stops responding |
| **Notification** | `notification` | Agent is waiting for user input |
| **Commit** | `commit` | A git commit was made |
| **SessionEnd** | `session_end` | Session terminated |

## Payload

Each hook receives a **JSON payload via stdin** with this structure:

```json
{
  "session_id": "uuid",
  "cwd": "/path/to/project",
  "triggered_at": "2025-01-01T00:00:00Z",
  "hook_event": {
    "event_type": "before_tool_use",
    "turn_id": "turn-1",
    "call_id": "call-1",
    "tool_name": "local_shell",
    "tool_kind": "local_shell",
    "tool_input": { ... }
  }
}
```

Environment variables are also set:
- `CODEX_HOOK_EVENT` — event type name
- `CODEX_HOOK_SESSION_ID` — session UUID
- `CODEX_HOOK_CWD` — working directory

## Exit Codes

- **0** — Success, continue normally
- **1** — Failed, but continue (logged as warning)
- **2** — Failed, **abort the operation** (e.g., prevent tool execution)

## Example

```bash
# .codex/hooks/before_tool_use
#!/bin/bash
# Log all tool executions
payload=$(cat)
echo "$payload" | jq -r '.hook_event.tool_name' >> /tmp/codex-tools.log

# Block dangerous commands
tool=$(echo "$payload" | jq -r '.hook_event.tool_name')
if [ "$tool" = "local_shell" ]; then
  cmd=$(echo "$payload" | jq -r '.hook_event.tool_input.params.command[0]')
  if [ "$cmd" = "rm" ]; then
    echo "Blocked rm command" >&2
    exit 2  # Abort
  fi
fi
```

## OpenClaw Integration

To monitor Codex sessions via OpenClaw (like Claude Code), install hooks that write events to a JSON file:

```bash
# .codex/hooks/after_agent
#!/bin/bash
SESSION_ID=$(echo "$(cat)" | jq -r '.session_id')
echo "$(cat)" > "/root/hook-events/codex-${SESSION_ID}-$(date +%s).json"
```

## File Extensions

Scripts can have extensions: `after_agent.sh`, `prompt.py`, etc. The stem must match the event name.
Multiple scripts for the same event are supported — they execute in filesystem order.
