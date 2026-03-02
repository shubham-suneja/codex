use super::*;
use codex_protocol::models::ContentItem;
use codex_protocol::models::MessagePhase;
use codex_protocol::models::ShellToolCallParams;
use pretty_assertions::assert_eq;

fn message(role: &str, text: &str, phase: Option<MessagePhase>) -> ResponseItem {
    ResponseItem::Message {
        id: None,
        role: role.to_string(),
        content: vec![ContentItem::InputText {
            text: text.to_string(),
        }],
        end_turn: None,
        phase,
    }
}

#[test]
fn extract_message_context_prefers_latest_assistant_final_answer() {
    let items = vec![
        message(
            "assistant",
            "older final answer",
            Some(MessagePhase::FinalAnswer),
        ),
        message(
            "assistant",
            "intermediate commentary",
            Some(MessagePhase::Commentary),
        ),
        message(
            "assistant",
            "newer final answer",
            Some(MessagePhase::FinalAnswer),
        ),
        message("user", "latest user message", None),
    ];

    let context = extract_message_context(&items);
    assert_eq!(
        context,
        (
            Some("latest user message".to_string()),
            Some("newer final answer".to_string()),
            Some("newer final answer".to_string()),
        )
    );
}

#[test]
fn extract_message_context_falls_back_when_no_final_answer_exists() {
    let items = vec![
        message(
            "assistant",
            "commentary one",
            Some(MessagePhase::Commentary),
        ),
        message("assistant", "commentary two", None),
        message("user", "latest user message", None),
    ];

    let context = extract_message_context(&items);
    assert_eq!(
        context,
        (
            Some("latest user message".to_string()),
            None,
            Some("commentary two".to_string()),
        )
    );
}

#[test]
fn build_tool_call_marks_mcp_calls_and_parses_arguments() {
    let payload = ToolPayload::Mcp {
        server: "codex_apps".to_string(),
        tool: "send_email".to_string(),
        raw_arguments: "{\"to\":\"user@example.com\"}".to_string(),
    };

    let tool_call = build_tool_call("call-1", "codex_apps__send_email", &payload);

    assert_eq!(
        tool_call,
        ArcToolCall {
            call_id: "call-1".to_string(),
            tool_name: "codex_apps__send_email".to_string(),
            kind: "mcp",
            server: Some("codex_apps".to_string()),
            mcp_tool_name: Some("send_email".to_string()),
            arguments: serde_json::json!({
                "to": "user@example.com"
            }),
        }
    );
}

#[test]
fn build_tool_call_serializes_local_shell_payload() {
    let payload = ToolPayload::LocalShell {
        params: ShellToolCallParams {
            command: vec!["echo".to_string(), "hello".to_string()],
            workdir: Some(".".to_string()),
            timeout_ms: Some(123),
            sandbox_permissions: None,
            additional_permissions: None,
            prefix_rule: None,
            justification: Some("test".to_string()),
        },
    };

    let tool_call = build_tool_call("call-2", "local_shell", &payload);

    assert_eq!(
        tool_call,
        ArcToolCall {
            call_id: "call-2".to_string(),
            tool_name: "local_shell".to_string(),
            kind: "local_shell",
            server: None,
            mcp_tool_name: None,
            arguments: serde_json::json!({
                "command": ["echo", "hello"],
                "workdir": ".",
                "timeout_ms": 123,
                "sandbox_permissions": null,
                "additional_permissions": null,
                "prefix_rule": null,
                "justification": "test",
            }),
        }
    );
}

#[test]
fn resolve_arc_endpoint_supports_relative_and_absolute_values() {
    assert_eq!(
        resolve_arc_endpoint("https://chatgpt.com/backend-api/", Some("")),
        None
    );
    assert_eq!(
        resolve_arc_endpoint("https://chatgpt.com/backend-api/", Some("/arc-check")),
        Some("https://chatgpt.com/backend-api/arc-check".to_string())
    );
    assert_eq!(
        resolve_arc_endpoint("https://chatgpt.com/backend-api/", Some("arc")),
        Some("https://chatgpt.com/backend-api/arc".to_string())
    );
    assert_eq!(
        resolve_arc_endpoint(
            "https://chatgpt.com/backend-api/",
            Some("https://monitor.test/arc")
        ),
        Some("https://monitor.test/arc".to_string())
    );
}

#[test]
fn monitor_response_prefers_first_class_contract_fields() {
    let response = ArcMonitorResponse {
        outcome: Some(ArcMonitorOutcomeWire::InterruptForUser),
        reason: Some("Need user confirmation".to_string()),
        message: Some("ignored".to_string()),
        monitor_request_id: Some("monitor-42".to_string()),
        allow: Some(true),
        blocked: Some(false),
        decision: Some("allow".to_string()),
    };

    assert_eq!(
        response.to_result(None),
        ArcMonitorResult {
            outcome: ArcMonitorOutcome::InterruptForUser,
            reason: "Need user confirmation".to_string(),
            monitor_request_id: "monitor-42".to_string(),
        }
    );
}

#[test]
fn monitor_response_compatibility_maps_blocked_decisions() {
    let response = ArcMonitorResponse {
        outcome: None,
        reason: None,
        message: Some("Unsafe action".to_string()),
        monitor_request_id: None,
        allow: None,
        blocked: None,
        decision: Some("blocked".to_string()),
    };

    let result = response.to_result(Some("fallback-9".to_string()));
    assert_eq!(result.outcome, ArcMonitorOutcome::InterruptForModel);
    assert_eq!(result.reason, "Unsafe action".to_string());
    assert_eq!(result.monitor_request_id, "fallback-9".to_string());
}

#[test]
fn build_monitor_input_uses_author_role_message_shape() {
    let input = build_monitor_input(
        Some("latest user message".to_string()),
        Some("assistant final".to_string()),
        Some("assistant final".to_string()),
    );

    assert_eq!(
        input,
        vec![
            ArcMonitorInputMessage {
                author: ArcMonitorInputAuthor {
                    role: "user".to_string(),
                },
                content: ArcMonitorInputContent {
                    parts: vec![ArcMonitorInputPart {
                        content_type: "text",
                        text: "latest user message".to_string(),
                    }],
                },
            },
            ArcMonitorInputMessage {
                author: ArcMonitorInputAuthor {
                    role: "assistant".to_string(),
                },
                content: ArcMonitorInputContent {
                    parts: vec![ArcMonitorInputPart {
                        content_type: "text",
                        text: "assistant final".to_string(),
                    }],
                },
            },
        ]
    );
}

#[test]
fn build_monitor_input_adds_latest_assistant_when_distinct_from_final() {
    let input = build_monitor_input(
        Some("latest user message".to_string()),
        Some("assistant final".to_string()),
        Some("assistant commentary".to_string()),
    );

    assert_eq!(input.len(), 3);
    assert_eq!(input[2].author.role, "assistant");
    assert_eq!(input[2].content.parts[0].text, "assistant commentary");
}

#[test]
fn monitor_response_parses_camel_case_outcome_alias() {
    let response: ArcMonitorResponse = serde_json::from_value(serde_json::json!({
        "outcome": "interruptForModel",
        "reason": "Blocked",
        "monitorRequestId": "m-1"
    }))
    .expect("parse monitor response");

    assert_eq!(
        response.to_result(None),
        ArcMonitorResult {
            outcome: ArcMonitorOutcome::InterruptForModel,
            reason: "Blocked".to_string(),
            monitor_request_id: "m-1".to_string(),
        }
    );
}

#[test]
fn monitor_response_parses_snake_case_outcome_alias() {
    let response: ArcMonitorResponse = serde_json::from_value(serde_json::json!({
        "outcome": "interrupt_for_user",
        "reason": "Need approval",
        "monitorRequestId": "m-2"
    }))
    .expect("parse monitor response");

    assert_eq!(
        response.to_result(None),
        ArcMonitorResult {
            outcome: ArcMonitorOutcome::InterruptForUser,
            reason: "Need approval".to_string(),
            monitor_request_id: "m-2".to_string(),
        }
    );
}
