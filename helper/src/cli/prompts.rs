//! Exact-request approval panels and per-connection scan start guards.
use super::terminal_input::{Control, InputLine};
use std::time::{Duration, Instant};
use webauthn_helper::PendingApproval;
pub(super) struct Prompt {
    pub(super) id: String,
    pub(super) origin: String,
    deadline: Instant,
}
#[derive(Default)]
pub(super) struct ApprovalPrompt {
    pub(super) current: Option<Prompt>,
}
impl ApprovalPrompt {
    pub(super) fn answer(
        &mut self,
        input: &InputLine,
    ) -> Result<(String, String, bool), &'static str> {
        let Some(prompt) = &self.current else {
            return Err("No pairing request is awaiting confirmation.");
        };
        if input.prompt_id.as_deref() != Some(prompt.id.as_str()) {
            return Err("That input belongs to an earlier request; no approval sent.");
        }
        let approve = match input.text.as_str() {
            "approve" => true,
            "reject" => false,
            _ => return Err("Use Left/Right or Tab, then Enter in the approval panel."),
        };
        let result = (prompt.id.clone(), prompt.origin.clone(), approve);
        self.current = None;
        Ok(result)
    }
}
#[derive(Default)]
pub(super) struct AutoScan {
    pub(super) attempted: Option<String>,
}
impl AutoScan {
    pub(super) fn should_start(
        &mut self,
        connection_id: Option<&str>,
        needs_restart: bool,
    ) -> bool {
        let Some(id) = connection_id else {
            self.attempted = None;
            return false;
        };
        if self.attempted.as_deref() == Some(id) || needs_restart {
            return false;
        }
        self.attempted = Some(id.into());
        true
    }
}
pub(super) fn display_prompt(
    prompt: &mut ApprovalPrompt,
    pending: Option<&PendingApproval>,
    controls: &std::sync::mpsc::Sender<Control>,
) {
    if prompt.current.as_ref().map(|p| p.id.as_str()) == pending.map(|p| p.id.as_str()) {
        return;
    }
    if let Some(old) = prompt.current.take() {
        let _ = controls.send(Control::Clear);
        if Instant::now() >= old.deadline {
            webauthn_helper::diagnostics::timed_out(&old.origin);
        } else {
            webauthn_helper::diagnostics::disconnected(&old.origin, true);
        }
    }
    if let Some(pending) = pending {
        prompt.current = Some(Prompt {
            id: pending.id.clone(),
            origin: pending.origin.clone(),
            deadline: Instant::now() + Duration::from_secs(pending.expires_in),
        });
        let _ = controls.send(Control::Prompt {
            id: pending.id.clone(),
            origin: pending.origin.clone(),
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use webauthn_helper::launch_incoming;
    fn pending(id: &str) -> PendingApproval {
        PendingApproval {
            id: id.into(),
            origin: "https://example.com:8443".into(),
            expires_in: 60,
        }
    }
    fn answer(id: Option<&str>, text: &str) -> InputLine {
        InputLine {
            text: text.into(),
            prompt_id: id.map(str::to_owned),
        }
    }
    #[test]
    fn panel_queues_exact_origin_and_requires_matching_request_bound_choice() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut prompt = ApprovalPrompt::default();
        display_prompt(&mut prompt, Some(&pending("first")), &tx);
        let Control::Prompt { id, origin } = rx.try_recv().unwrap() else {
            panic!("expected panel");
        };
        assert_eq!(id, "first");
        assert_eq!(origin, "https://example.com:8443");
        display_prompt(&mut prompt, Some(&pending("first")), &tx);
        assert!(rx.try_recv().is_err());
        assert!(prompt.answer(&answer(None, "approve")).is_err());
        assert!(prompt.answer(&answer(Some("first"), "")).is_err());
        assert!(prompt.answer(&answer(Some("first"), "yes")).is_err());
        assert_eq!(
            prompt.answer(&answer(Some("first"), "approve")),
            Ok(("first".into(), origin, true))
        );
        assert!(prompt.current.is_none());
    }

    #[test]
    fn rejected_choice_is_bound_and_old_answer_cannot_approve_replacement() {
        let (tx, _) = std::sync::mpsc::channel();
        let mut prompt = ApprovalPrompt::default();
        display_prompt(&mut prompt, Some(&pending("old")), &tx);
        display_prompt(&mut prompt, None, &tx);
        assert!(prompt.current.is_none());
        display_prompt(&mut prompt, Some(&pending("new")), &tx);
        assert!(prompt.answer(&answer(Some("old"), "approve")).is_err());
        assert!(!prompt.answer(&answer(Some("new"), "reject")).unwrap().2);
    }

    #[test]
    fn bluetooth_starts_once_only_after_pairing_and_never_retries_errors() {
        let mut auto = AutoScan::default();
        assert!(!auto.should_start(None, false));
        assert!(auto.should_start(Some("first"), false));
        assert!(!auto.should_start(Some("first"), false));
        assert!(!auto.should_start(None, false));
        assert!(!auto.should_start(Some("first"), true));
        assert!(auto.should_start(Some("first"), false));
    }

    #[test]
    fn rapid_reconnect_starts_ble_even_when_poll_misses_disconnect() {
        let mut auto = AutoScan::default();
        assert!(auto.should_start(Some("first"), false));
        assert!(auto.should_start(Some("next"), false));
        assert!(!auto.should_start(Some("next"), false));
    }

    #[tokio::test]
    async fn request_bound_panel_choice_approves_exact_socket_and_schedules_ble_once() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
        let handle = launch_incoming(Some(10233)).await.unwrap();
        let mut request = handle.websocket_url().into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", "https://example.com".parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        socket
            .send(Message::Text(
                serde_json::json!({"type":"pair","token":"OneUseIncomingToken0123456789ABCD"})
                    .to_string(),
            ))
            .await
            .unwrap();
        let pending = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(pending) = handle.snapshot().await.pending_approval {
                    return pending;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut prompt = ApprovalPrompt::default();
        let (tx, _) = std::sync::mpsc::channel();
        display_prompt(&mut prompt, Some(&pending), &tx);
        let (id, _, approve) = prompt
            .answer(&answer(Some(&pending.id), "approve"))
            .unwrap();
        assert!(approve);
        handle.decide_pending(&id, approve).await.unwrap();
        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reply.into_text().unwrap()).unwrap()
                ["state"],
            "paired"
        );
        let snapshot = handle.snapshot().await;
        let mut auto = AutoScan::default();
        assert!(auto.should_start(snapshot.connection_id.as_deref(), snapshot.needs_restart));
        assert!(!auto.should_start(snapshot.connection_id.as_deref(), snapshot.needs_restart));
        // Verify the production decision to start without touching an OS adapter.
        assert!(!snapshot.scanning);
        socket.close(None).await.unwrap();
        handle.shutdown().await.unwrap();
    }
}
