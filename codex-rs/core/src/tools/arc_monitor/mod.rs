use std::time::Duration;

use crate::compact::content_items_to_text;
use crate::default_client::create_client;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use codex_protocol::models::MessagePhase;
use codex_protocol::models::ResponseItem;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use tracing::warn;
use uuid::Uuid;

const ARC_ENDPOINT_PATH: &str = "/arc";
const ARC_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArcMonitorOutcome {
    None,
    InterruptForUser,
    InterruptForModel,
    InterruptForMonitor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArcMonitorResult {
    pub(crate) outcome: ArcMonitorOutcome,
    pub(crate) reason: String,
    pub(crate) monitor_request_id: String,
}

impl ArcMonitorResult {
    fn none(reason: impl Into<String>) -> Self {
        Self {
            outcome: ArcMonitorOutcome::None,
            reason: reason.into(),
            monitor_request_id: String::new(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorRequest {
    thread_id: String,
    turn_id: String,
    input: Vec<ArcMonitorInputMessage>,
    policies: ArcMonitorPoliciesRequest,
    action: ArcToolCall,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorInputMessage {
    author: ArcMonitorInputAuthor,
    content: ArcMonitorInputContent,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorInputAuthor {
    role: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorInputContent {
    parts: Vec<ArcMonitorInputPart>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorInputPart {
    content_type: &'static str,
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorPoliciesRequest {
    user: String,
    developer: String,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArcToolCall {
    call_id: String,
    tool_name: String,
    kind: &'static str,
    server: Option<String>,
    mcp_tool_name: Option<String>,
    arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ArcMonitorOutcomeWire {
    None,
    #[serde(alias = "interrupt_for_user", alias = "interruptForUser")]
    InterruptForUser,
    #[serde(alias = "interrupt_for_model", alias = "interruptForModel")]
    InterruptForModel,
    #[serde(alias = "interrupt_for_monitor", alias = "interruptForMonitor")]
    InterruptForMonitor,
}

impl From<ArcMonitorOutcomeWire> for ArcMonitorOutcome {
    fn from(value: ArcMonitorOutcomeWire) -> Self {
        match value {
            ArcMonitorOutcomeWire::None => ArcMonitorOutcome::None,
            ArcMonitorOutcomeWire::InterruptForUser => ArcMonitorOutcome::InterruptForUser,
            ArcMonitorOutcomeWire::InterruptForModel => ArcMonitorOutcome::InterruptForModel,
            ArcMonitorOutcomeWire::InterruptForMonitor => ArcMonitorOutcome::InterruptForMonitor,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArcMonitorResponse {
    outcome: Option<ArcMonitorOutcomeWire>,
    reason: Option<String>,
    message: Option<String>,
    monitor_request_id: Option<String>,
    // Compatibility fields for older implementations.
    allow: Option<bool>,
    blocked: Option<bool>,
    decision: Option<String>,
}

impl ArcMonitorResponse {
    fn to_result(self, fallback_request_id: Option<String>) -> ArcMonitorResult {
        let outcome = match self.outcome {
            Some(outcome) => outcome.into(),
            None => self.compatibility_outcome(),
        };

        let reason = self
            .reason
            .or(self.message)
            .map(|reason| reason.trim().to_string())
            .filter(|reason| !reason.is_empty())
            .unwrap_or_else(|| match outcome {
                ArcMonitorOutcome::None => "monitor allowed action".to_string(),
                ArcMonitorOutcome::InterruptForUser => {
                    "monitor requested user intervention".to_string()
                }
                ArcMonitorOutcome::InterruptForModel => "blocked by monitor".to_string(),
                ArcMonitorOutcome::InterruptForMonitor => "monitor interrupted action".to_string(),
            });

        let monitor_request_id = self
            .monitor_request_id
            .filter(|id| !id.trim().is_empty())
            .or(fallback_request_id)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        ArcMonitorResult {
            outcome,
            reason,
            monitor_request_id,
        }
    }

    fn compatibility_outcome(&self) -> ArcMonitorOutcome {
        if let Some(decision) = self.decision.as_deref() {
            let normalized = decision.trim().to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "deny" | "denied" | "block" | "blocked" | "reject" | "rejected"
            ) {
                return ArcMonitorOutcome::InterruptForModel;
            }
            if matches!(
                normalized.as_str(),
                "allow" | "approved" | "approve" | "pass" | "passed"
            ) {
                return ArcMonitorOutcome::None;
            }
        }

        if let Some(allow) = self.allow {
            return if allow {
                ArcMonitorOutcome::None
            } else {
                ArcMonitorOutcome::InterruptForModel
            };
        }
        if let Some(blocked) = self.blocked {
            return if blocked {
                ArcMonitorOutcome::InterruptForModel
            } else {
                ArcMonitorOutcome::None
            };
        }

        ArcMonitorOutcome::None
    }
}

pub(crate) async fn run_arc_monitor(invocation: &ToolInvocation) -> ArcMonitorResult {
    let Some(endpoint) = resolve_arc_endpoint(
        invocation.turn.config.chatgpt_base_url.as_str(),
        invocation.turn.config.arc_monitor.endpoint.as_deref(),
    ) else {
        return ArcMonitorResult::none("monitor disabled");
    };

    let mut access_token = None;
    let mut account_id = None;
    if let Some(auth) = invocation.session.services.auth_manager.auth().await
        && auth.is_chatgpt_auth()
    {
        access_token = match auth.get_token() {
            Ok(token) => Some(token),
            Err(err) => {
                warn!("arc monitor token unavailable: {err}");
                None
            }
        };
        account_id = auth.get_account_id();
    }

    let history = invocation.session.clone_history().await;
    let (latest_user_message, latest_assistant_final_message, latest_assistant_message) =
        extract_message_context(history.raw_items());
    let input = build_monitor_input(
        latest_user_message,
        latest_assistant_final_message,
        latest_assistant_message,
    );

    let request = ArcMonitorRequest {
        thread_id: invocation.session.conversation_id.to_string(),
        turn_id: invocation.turn.sub_id.clone(),
        input,
        policies: ArcMonitorPoliciesRequest {
            user: invocation.turn.config.arc_monitor.policies.user.clone(),
            developer: invocation
                .turn
                .config
                .arc_monitor
                .policies
                .developer
                .clone(),
        },
        action: build_tool_call(
            invocation.call_id.as_str(),
            invocation.tool_name.as_str(),
            &invocation.payload,
        ),
    };

    let mut request_builder = create_client()
        .post(endpoint.as_str())
        .timeout(ARC_TIMEOUT)
        .header("Content-Type", "application/json")
        .json(&request);
    if let Some(access_token) = access_token {
        request_builder = request_builder.bearer_auth(access_token);
    }
    if let Some(account_id) = account_id {
        request_builder = request_builder.header("chatgpt-account-id", account_id);
    }

    let response = request_builder.send().await;
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            return monitor_error_result(
                "monitor request failed",
                Some(format!("{}: {err}", endpoint.as_str())),
            );
        }
    };

    let fallback_request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .filter(|id| !id.trim().is_empty());

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        warn!("arc monitor failed with status {status}: {body}");
        return monitor_error_result(
            format!("monitor request failed with status {status}"),
            Some(body),
        );
    }

    match response.json::<ArcMonitorResponse>().await {
        Ok(body) => body.to_result(fallback_request_id),
        Err(err) => monitor_error_result("monitor response decode failed", Some(err.to_string())),
    }
}

fn monitor_error_result(reason: impl Into<String>, detail: Option<String>) -> ArcMonitorResult {
    let reason = reason.into();
    if let Some(detail) = detail.as_deref() {
        warn!("{reason}: {detail}");
    } else {
        warn!("{reason}");
    }

    let reason = detail
        .map(|detail| format!("{reason}: {detail}"))
        .unwrap_or(reason);
    ArcMonitorResult {
        outcome: ArcMonitorOutcome::InterruptForMonitor,
        reason,
        monitor_request_id: Uuid::new_v4().to_string(),
    }
}

fn resolve_arc_endpoint(
    chatgpt_base_url: &str,
    configured_endpoint: Option<&str>,
) -> Option<String> {
    let configured_endpoint = configured_endpoint
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if configured_endpoint.starts_with("https://") || configured_endpoint.starts_with("http://") {
        return Some(configured_endpoint.to_string());
    }

    let base = chatgpt_base_url.trim_end_matches('/');
    if configured_endpoint.starts_with('/') {
        Some(format!("{base}{configured_endpoint}"))
    } else if configured_endpoint == ARC_ENDPOINT_PATH.trim_start_matches('/') {
        Some(format!("{base}{ARC_ENDPOINT_PATH}"))
    } else {
        Some(format!("{base}/{configured_endpoint}"))
    }
}

fn build_tool_call(call_id: &str, tool_name: &str, payload: &ToolPayload) -> ArcToolCall {
    match payload {
        ToolPayload::Function { arguments } => ArcToolCall {
            call_id: call_id.to_string(),
            tool_name: tool_name.to_string(),
            kind: "function",
            server: None,
            mcp_tool_name: None,
            arguments: parse_json_or_text(arguments),
        },
        ToolPayload::Custom { input } => ArcToolCall {
            call_id: call_id.to_string(),
            tool_name: tool_name.to_string(),
            kind: "custom",
            server: None,
            mcp_tool_name: None,
            arguments: Value::String(input.clone()),
        },
        ToolPayload::LocalShell { params } => ArcToolCall {
            call_id: call_id.to_string(),
            tool_name: tool_name.to_string(),
            kind: "local_shell",
            server: None,
            mcp_tool_name: None,
            arguments: serde_json::json!({
                "command": params.command,
                "workdir": params.workdir,
                "timeout_ms": params.timeout_ms,
                "sandbox_permissions": params.sandbox_permissions,
                "additional_permissions": params.additional_permissions,
                "prefix_rule": params.prefix_rule,
                "justification": params.justification,
            }),
        },
        ToolPayload::Mcp {
            server,
            tool,
            raw_arguments,
        } => ArcToolCall {
            call_id: call_id.to_string(),
            tool_name: tool_name.to_string(),
            kind: "mcp",
            server: Some(server.clone()),
            mcp_tool_name: Some(tool.clone()),
            arguments: parse_json_or_text(raw_arguments),
        },
    }
}

fn parse_json_or_text(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}

fn build_monitor_input(
    latest_user_message: Option<String>,
    latest_assistant_final_message: Option<String>,
    latest_assistant_message: Option<String>,
) -> Vec<ArcMonitorInputMessage> {
    let mut input = Vec::new();

    if let Some(text) = latest_user_message {
        input.push(build_monitor_input_message("user", text));
    }

    if let Some(final_text) = latest_assistant_final_message {
        input.push(build_monitor_input_message("assistant", final_text.clone()));
        if let Some(latest_text) = latest_assistant_message
            && latest_text != final_text
        {
            input.push(build_monitor_input_message("assistant", latest_text));
        }
    } else if let Some(latest_text) = latest_assistant_message {
        input.push(build_monitor_input_message("assistant", latest_text));
    }

    input
}

fn build_monitor_input_message(role: &str, text: String) -> ArcMonitorInputMessage {
    ArcMonitorInputMessage {
        author: ArcMonitorInputAuthor {
            role: role.to_string(),
        },
        content: ArcMonitorInputContent {
            parts: vec![ArcMonitorInputPart {
                content_type: "text",
                text,
            }],
        },
    }
}

fn extract_message_context(
    items: &[ResponseItem],
) -> (Option<String>, Option<String>, Option<String>) {
    let mut latest_user_message = None;
    let mut latest_assistant_final_message = None;
    let mut latest_assistant_message = None;

    for item in items.iter().rev() {
        let ResponseItem::Message {
            role,
            content,
            phase,
            ..
        } = item
        else {
            continue;
        };

        let Some(text) = content_items_to_text(content) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }

        if role == "user" && latest_user_message.is_none() {
            latest_user_message = Some(text.clone());
        }

        if role == "assistant" {
            if latest_assistant_message.is_none() {
                latest_assistant_message = Some(text.clone());
            }
            if latest_assistant_final_message.is_none()
                && matches!(phase, Some(MessagePhase::FinalAnswer))
            {
                latest_assistant_final_message = Some(text.clone());
            }
        }

        if latest_user_message.is_some()
            && latest_assistant_final_message.is_some()
            && latest_assistant_message.is_some()
        {
            break;
        }
    }

    (
        latest_user_message,
        latest_assistant_final_message,
        latest_assistant_message,
    )
}

#[cfg(test)]
mod tests;
