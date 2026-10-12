//! Minimal native listener and approval controls. Never opens a browser.
mod controller;
mod logging;
use controller::{backend, parse_listen_address, CloseState, Command, Event, LatestSnapshot};
use eframe::egui;
use std::{
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};
use webauthn_helper::{BleState, PendingApproval, Snapshot, DEFAULT_PORT};
const WINDOW_TITLE: &str = "WebAuthn Helper Desktop";
fn ble_status(snapshot: Option<&Snapshot>, enabled: bool) -> (&'static str, bool) {
    match snapshot
        .map(|snapshot| snapshot.ble_state)
        .unwrap_or(BleState::Stopped)
    {
        BleState::Stopped if !enabled => ("BLE: disabled", false),
        BleState::Stopped => ("BLE: stopped", false),
        BleState::Starting => ("BLE: starting", false),
        BleState::Scanning => ("BLE: listening for phone", true),
        BleState::Stopping => ("BLE: stopping", false),
        BleState::Unavailable => ("BLE: unavailable", false),
        BleState::CleanupFailed => ("BLE: cleanup unconfirmed", false),
    }
}

fn approval_question(ble: bool, usb: bool) -> &'static str {
    match (ble, usb) {
        (true, true) => "Allow pairing, BLE and USB for this origin?",
        (true, false) => "Allow pairing and BLE for this origin?",
        (false, true) => "Allow pairing and USB for this origin?",
        (false, false) => "Allow pairing for this origin?",
    }
}

fn usb_status(
    status: &webauthn_helper::fido_device::Status,
    enabled: bool,
) -> (&'static str, bool) {
    if status.cleanup_unconfirmed {
        return ("USB: cleanup unconfirmed", false);
    }
    if !enabled {
        return (
            if status.attached {
                "USB: stopping"
            } else {
                "USB: disabled"
            },
            false,
        );
    }
    if !status.choices.is_empty() {
        return ("USB: select device", false);
    }
    if status.attached {
        return if status.message == "USB: ready" {
            ("USB: connected", true)
        } else {
            ("USB: waiting for browser", false)
        };
    }
    if status.message.contains("unavailable") || status.message.contains("could not start") {
        ("USB: unavailable", false)
    } else if status.message.contains("finding") {
        ("USB: finding device", false)
    } else {
        ("USB: disconnected", false)
    }
}

fn status_row(ui: &mut egui::Ui, label: &str, active: bool, enabled: Option<&mut bool>) -> bool {
    ui.horizontal(|ui| {
        // Every row reserves the same checkbox column, including read-only rows.
        let size = ui
            .spacing()
            .interact_size
            .y
            .max(ui.spacing().icon_width)
            .max(20.0);
        ui.spacing_mut().interact_size.y = size;
        let checkbox = if let Some(enabled) = enabled {
            Some(ui.add_sized(
                egui::Vec2::splat(size),
                egui::Checkbox::without_text(enabled),
            ))
        } else {
            ui.allocate_exact_size(egui::Vec2::splat(size), egui::Sense::hover());
            None
        };
        let label = status_indicator(ui, label, active);
        checkbox.is_some_and(|checkbox| checkbox.labelled_by(label.id).changed())
    })
    .inner
}

fn status_indicator(ui: &mut egui::Ui, label: &str, active: bool) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 20.0), egui::Sense::hover());
    let color = if active {
        egui::Color32::from_rgb(70, 170, 110)
    } else {
        ui.visuals().weak_text_color()
    };
    ui.painter().circle_filled(rect.center(), 4.0, color);
    ui.label(label)
}

struct Desktop {
    commands: Sender<Command>,
    events: Receiver<Event>,
    worker: Option<JoinHandle<()>>,
    latest: LatestSnapshot,
    close_state: CloseState,
    address: String,
    listening: bool,
    snapshot: Option<Snapshot>,
    pending: Option<PendingApproval>,
    busy: bool,
    fatal: bool,
    error: Option<String>,
    usb_enabled: bool,
    ble_enabled: bool,
    usb: webauthn_helper::fido_device::Status,
}
impl Desktop {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        let (commands, command_rx) = mpsc::channel();
        let (event_tx, events) = mpsc::channel();
        let repaint = context.egui_ctx.clone();
        let latest = Arc::new(Mutex::new(None));
        let worker_latest = latest.clone();
        let worker = thread::spawn(move || backend(command_rx, event_tx, worker_latest, repaint));
        Self {
            commands,
            events,
            worker: Some(worker),
            latest,
            close_state: CloseState::Open,
            address: format!("127.0.0.1:{}", DEFAULT_PORT),
            listening: false,
            snapshot: None,
            pending: None,
            busy: false,
            fatal: false,
            error: None,
            usb_enabled: true,
            ble_enabled: true,
            usb: Default::default(),
        }
    }
    fn command(&mut self, command: Command) {
        if self.commands.send(command).is_ok() {
            self.busy = true;
            self.error = None;
        } else {
            self.fatal = true;
            self.error = Some("The listener worker is unavailable. Reopen the app.".into());
        }
    }
    fn toggle_listener(&mut self) {
        if self.busy || self.fatal || self.close_state != CloseState::Open {
            return;
        }
        if self.listening {
            self.pending = None;
            self.command(Command::StopListener);
        } else {
            match parse_listen_address(&self.address) {
                Ok(port) => self.command(Command::StartListener(port)),
                Err(message) => self.error = Some(message.into()),
            }
        }
    }
    fn receive(&mut self) {
        loop {
            let event = match self.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.close_state.finish(Err("The listener worker exited without confirming cleanup. Check OS Bluetooth controls.".into()));
                    if self.close_state == CloseState::Open && !self.fatal {
                        self.fatal = true;
                        self.error =
                            Some("The listener worker is unavailable. Reopen the app.".into());
                    }
                    break;
                }
            };
            match event {
                Event::Listening(address) => {
                    self.address = address.strip_prefix("ws://").unwrap_or(&address).into();
                    self.listening = true;
                    self.busy = false;
                }
                Event::Stopped(result) => {
                    self.busy = false;
                    match result {
                        Ok(()) => {
                            self.listening = false;
                            self.snapshot = None;
                            self.pending = None;
                        }
                        Err(message) => {
                            self.fatal = true;
                            self.error = Some(message);
                        }
                    }
                }
                Event::Usb(status) => {
                    self.usb = status;
                }
                Event::Allowed => {
                    self.busy = false;
                }
                Event::Approved => {
                    self.busy = false;
                    self.pending = None;
                }
                Event::Failed(message) => {
                    self.busy = false;
                    self.error = Some(message);
                }
                Event::Fatal(message) => {
                    self.busy = false;
                    self.fatal = true;
                    self.error = Some(message);
                }
                Event::ShutdownFinished(result) => {
                    self.close_state.finish(result);
                    self.busy = false;
                    self.fatal = true;
                }
            }
        }
        let snapshot = self.latest.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(snapshot) = snapshot {
            self.pending = if self.listening && !self.busy && !self.fatal {
                snapshot.pending_approval.clone()
            } else {
                None
            };
            self.snapshot = Some(snapshot);
        }
    }
    fn request_close(&mut self) {
        if !self.close_state.begin() {
            return;
        }
        self.pending = None;
        self.busy = true;
        if self.fatal && !self.listening {
            self.close_state.finish(Ok(()));
        } else if self.commands.send(Command::Shutdown).is_err() {
            self.close_state.finish(Err(
                "The listener worker stopped unexpectedly. Check OS Bluetooth controls.".into(),
            ));
        }
    }
    fn close(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Desktop {
    fn show(&mut self, ctx: &egui::Context) {
        self.receive();
        if ctx.input(|input| input.viewport().close_requested())
            && self.close_state != CloseState::ReadyToExit
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.request_close();
        }
        if self.close_state == CloseState::ReadyToExit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space((ui.available_height() - 230.0).max(0.0) / 2.0);
            ui.vertical_centered(|ui| {
                ui.set_max_width(420.0);
                ui.label(egui::RichText::new("Listen Address").size(18.0));
                ui.add_space(8.0);
                ui.add_enabled_ui(!self.listening && !self.busy && !self.fatal, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.address)
                            .font(egui::FontId::monospace(28.0))
                            .horizontal_align(egui::Align::Center)
                            .margin(egui::vec2(12.0, 12.0))
                            .desired_width(ui.available_width()),
                    );
                });
                ui.add_space(12.0);
                let label = if self.busy {
                    "Please wait…"
                } else if self.listening {
                    "Stop listening"
                } else {
                    "Start listening"
                };
                if ui
                    .add_enabled(
                        !self.busy && !self.fatal && self.close_state == CloseState::Open,
                        egui::Button::new(egui::RichText::new(label).size(19.0))
                            .min_size(egui::vec2(210.0, 44.0)),
                    )
                    .clicked()
                {
                    self.toggle_listener();
                }
                ui.add_space(20.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(285.0, 105.0),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        status_row(
                            ui,
                            if self.fatal && self.listening {
                                "Listener: cleanup unconfirmed"
                            } else if self.listening {
                                "Listener: running"
                            } else {
                                "Listener: stopped"
                            },
                            self.listening && !self.fatal,
                            None,
                        );
                        let connected = self
                            .snapshot
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.connected);
                        status_row(
                            ui,
                            if connected {
                                "Browser: connected"
                            } else {
                                "Browser: disconnected"
                            },
                            connected,
                            None,
                        );
                        let (label, active) = ble_status(self.snapshot.as_ref(), self.ble_enabled);
                        if status_row(ui, label, active, Some(&mut self.ble_enabled)) {
                            let _ = self.commands.send(Command::BleEnabled(self.ble_enabled));
                        }
                        let (label, active) = usb_status(&self.usb, self.usb_enabled);
                        if status_row(ui, label, active, Some(&mut self.usb_enabled)) {
                            let _ = self.commands.send(Command::UsbEnabled(self.usb_enabled));
                        }
                    },
                );
                if let Some(snapshot) = self.snapshot.clone() {
                    if snapshot.withholding_saturated {
                        ui.label(
                            "Too many withheld Origins. Restart the helper to reset local consent.",
                        );
                    } else {
                        for origin in snapshot.withheld_origins {
                            ui.monospace(&origin);
                            if ui
                                .add_enabled(
                                    !self.busy && !self.fatal,
                                    egui::Button::new("Allow a new pairing request"),
                                )
                                .clicked()
                            {
                                self.command(Command::AllowPairing(origin));
                            }
                        }
                    }
                }
                if let Some(error) = &self.error {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                }
                if let Some(snapshot) = &self.snapshot {
                    if matches!(
                        snapshot.ble_state,
                        BleState::Unavailable | BleState::CleanupFailed
                    ) {
                        ui.colored_label(ui.visuals().error_fg_color, &snapshot.status);
                    }
                }
            });
        });
        if self.listening && self.close_state == CloseState::Open {
            if let Some(pending) = self.pending.clone() {
                egui::Window::new("Approve browser pairing")
                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                    .collapsible(false)
                    .resizable(false)
                    .default_width(410.0)
                    .show(ctx, |ui| {
                        ui.monospace(&pending.origin);
                        ui.add_space(8.0);
                        ui.label(approval_question(self.ble_enabled, self.usb_enabled));
                        if let Some(error) = &self.error {
                            ui.colored_label(ui.visuals().error_fg_color, error);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            // Keep the visual and keyboard order while aligning the group right.
                            let button_labels = ["Approve", "Reject"].map(|label| {
                                egui::WidgetText::from(label).into_galley(
                                    ui,
                                    Some(egui::TextWrapMode::Extend),
                                    f32::INFINITY,
                                    egui::TextStyle::Button,
                                )
                            });
                            let width = button_labels
                                .iter()
                                .map(|label| label.size().x)
                                .sum::<f32>()
                                + 4.0 * ui.spacing().button_padding.x
                                + ui.spacing().item_spacing.x;
                            ui.add_space((ui.available_width() - width).max(0.0));
                            let [approve, reject] = button_labels;
                            if ui
                                .add_enabled(!self.busy, egui::Button::new(approve))
                                .clicked()
                            {
                                self.command(Command::DecidePairing {
                                    id: pending.id.clone(),
                                    approve: true,
                                });
                            }
                            if ui
                                .add_enabled(!self.busy, egui::Button::new(reject))
                                .clicked()
                            {
                                self.command(Command::DecidePairing {
                                    id: pending.id,
                                    approve: false,
                                });
                            }
                        });
                    });
            }
        }
        if self.listening && self.usb_enabled && !self.usb.choices.is_empty() {
            egui::Window::new("Select USB device")
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    for choice in &self.usb.choices {
                        if ui
                            .button(format!("{} ({})", choice.label, &choice.id[..8]))
                            .clicked()
                        {
                            let _ = self.commands.send(Command::UsbSelect(choice.id.clone()));
                        }
                    }
                });
        }
        match &self.close_state {
            CloseState::Stopping => {
                egui::Window::new("Stopping listener")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.spinner();
                        ui.label(
                            "Revoking pairing and waiting for Bluetooth and the listener to stop…",
                        );
                    });
            }
            CloseState::Failed(message) => {
                let message = message.clone();
                egui::Window::new("Cleanup could not be confirmed")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(message);
                        ui.label("Check OS Bluetooth controls. Exiting does not confirm cleanup.");
                        if ui.button("Exit anyway").clicked() {
                            self.close_state = CloseState::ReadyToExit;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
            }
            _ => {}
        }
    }
}
impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.show(ctx);
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.close();
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn run() -> eframe::Result {
    logging::init();
    eframe::run_native(
        WINDOW_TITLE,
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([570.0, 500.0])
                .with_min_inner_size([460.0, 340.0]),
            ..Default::default()
        },
        Box::new(|context| Ok(Box::new(Desktop::new(context)))),
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    fn controller() -> (Desktop, Receiver<Command>, Sender<Event>) {
        let (commands, receiver) = mpsc::channel();
        let (event_tx, events) = mpsc::channel();
        (
            Desktop {
                commands,
                events,
                worker: None,
                latest: Arc::new(Mutex::new(None)),
                close_state: CloseState::Open,
                address: format!("127.0.0.1:{DEFAULT_PORT}"),
                listening: false,
                snapshot: None,
                pending: None,
                busy: false,
                fatal: false,
                error: None,
                usb_enabled: true,
                ble_enabled: true,
                usb: Default::default(),
            },
            receiver,
            event_tx,
        )
    }
    #[test]
    fn rendered_desktop_is_compact_centered_and_channel_controls_are_visible() {
        fn labels(shape: &egui::epaint::Shape, found: &mut Vec<(String, f32)>) {
            match shape {
                egui::epaint::Shape::Text(text) => found.push((
                    text.galley.text().into(),
                    text.pos.x + text.galley.size().x / 2.0,
                )),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        labels(shape, found);
                    }
                }
                _ => {}
            }
        }
        let (mut desktop, _commands, _events) = controller();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(570.0, 500.0),
            )),
            ..Default::default()
        };
        let _ = ctx.run(input.clone(), |ctx| desktop.show(ctx));
        let output = ctx.run(input, |ctx| desktop.show(ctx));
        let mut found = Vec::new();
        for shape in output.shapes {
            labels(&shape.shape, &mut found);
        }
        for wanted in [
            "Listen Address",
            "127.0.0.1:10233",
            "Start listening",
            "Listener: stopped",
            "Browser: disconnected",
            "BLE: stopped",
            "USB: disconnected",
        ] {
            assert!(
                found.iter().any(|(text, _)| text == wanted),
                "Missing {wanted}: {found:?}"
            );
        }
        for (text, center) in &found {
            if text == "127.0.0.1:10233" || text == "Start listening" {
                assert!((center - 285.0).abs() < 2.0, "{text}: {center}");
            }
            assert!(
                text != "BLE"
                    && text != "USB"
                    && !text.contains("Detach")
                    && !text.contains("Retry USB")
                    && !text.contains("FIDO")
                    && !text.contains("matching key")
            );
        }
        assert_eq!(WINDOW_TITLE, "WebAuthn Helper Desktop");
    }

    #[test]
    fn rendered_status_rows_share_columns_and_channel_checkboxes_remain_live() {
        fn geometry(
            shape: &egui::epaint::Shape,
            icon_width: f32,
            labels: &mut Vec<(String, egui::Rect)>,
            checkboxes: &mut Vec<egui::Rect>,
            dots: &mut Vec<egui::Pos2>,
        ) {
            match shape {
                egui::epaint::Shape::Text(text) => labels.push((
                    text.galley.text().into(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::epaint::Shape::Rect(rect)
                    if (rect.rect.width() - icon_width).abs() < 0.5
                        && (rect.rect.height() - icon_width).abs() < 0.5 =>
                {
                    checkboxes.push(rect.rect);
                }
                egui::epaint::Shape::Circle(circle) if circle.radius == 4.0 => {
                    dots.push(circle.center);
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        geometry(shape, icon_width, labels, checkboxes, dots);
                    }
                }
                _ => {}
            }
        }
        let (mut desktop, commands, _events) = controller();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(570.0, 500.0),
            )),
            ..Default::default()
        };
        let _ = ctx.run(input.clone(), |ctx| desktop.show(ctx));
        let output = ctx.run(input.clone(), |ctx| desktop.show(ctx));
        let (mut labels, mut checkboxes, mut dots) = (Vec::new(), Vec::new(), Vec::new());
        for shape in output.shapes {
            geometry(
                &shape.shape,
                ctx.style().spacing.icon_width,
                &mut labels,
                &mut checkboxes,
                &mut dots,
            );
        }
        assert_eq!(checkboxes.len(), 2, "{checkboxes:?}");
        assert_eq!(dots.len(), 4, "{dots:?}");
        let mut columns: Option<(f32, f32)> = None;
        let mut row_centers = Vec::new();
        for wanted in [
            "Listener: stopped",
            "Browser: disconnected",
            "BLE: stopped",
            "USB: disconnected",
        ] {
            let label = labels.iter().find(|(text, _)| text == wanted).unwrap().1;
            let row_dots: Vec<_> = dots
                .iter()
                .filter(|dot| (dot.y - label.center().y).abs() < 0.5)
                .collect();
            assert_eq!(row_dots.len(), 1, "Dot must share {wanted}'s row: {dots:?}");
            let dot = row_dots[0];
            assert!(dot.x + 4.0 < label.left());
            if let Some((dot_x, text_x)) = columns {
                assert!(
                    (dot.x - dot_x).abs() < 0.5,
                    "Dot column differs for {wanted}"
                );
                assert!(
                    (label.left() - text_x).abs() < 0.5,
                    "Text column differs for {wanted}"
                );
            } else {
                columns = Some((dot.x, label.left()));
            }
            let row_checkboxes: Vec<_> = checkboxes
                .iter()
                .filter(|rect| (rect.center().y - label.center().y).abs() < 0.5)
                .collect();
            assert_eq!(
                row_checkboxes.len(),
                usize::from(wanted.starts_with("BLE:") || wanted.starts_with("USB:")),
                "Only channel rows have a checkbox: {wanted}"
            );
            row_centers.push(label.center().y);
        }
        let row_spacing = row_centers[1] - row_centers[0];
        assert!(row_spacing >= 20.0);
        for pair in row_centers.windows(2) {
            assert!((pair[1] - pair[0] - row_spacing).abs() < 0.5);
        }
        assert!((checkboxes[0].left() - checkboxes[1].left()).abs() < 0.5);
        for wanted in ["BLE: stopped", "USB: disconnected"] {
            let label = labels.iter().find(|(text, _)| text == wanted).unwrap().1;
            let checkbox = checkboxes
                .iter()
                .find(|rect| (rect.center().y - label.center().y).abs() < 0.5)
                .unwrap_or_else(|| panic!("Checkbox is not on {wanted}'s row: {checkboxes:?}; label={label:?}; dots={dots:?}"));
            let dot = dots
                .iter()
                .find(|dot| (dot.y - label.center().y).abs() < 0.5)
                .unwrap_or_else(|| panic!("Dot is not on {wanted}'s row: {dots:?}"));
            assert!(
                checkbox.right() < dot.x - 4.0 && dot.x + 4.0 < label.left(),
                "Expected checkbox, dot, label for {wanted}: {checkbox:?}, {dot:?}, {label:?}"
            );
            // The rendered box remains the real channel control, not decoration.
            let position = checkbox.center();
            for pressed in [true, false] {
                let _ = ctx.run(
                    egui::RawInput {
                        events: vec![
                            egui::Event::PointerMoved(position),
                            egui::Event::PointerButton {
                                pos: position,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::NONE,
                            },
                        ],
                        ..input.clone()
                    },
                    |ctx| desktop.show(ctx),
                );
            }
            let command = commands
                .try_recv()
                .expect("Checkbox must dispatch a toggle");
            assert!(matches!(
                (wanted, command),
                ("BLE: stopped", Command::BleEnabled(false))
                    | ("USB: disconnected", Command::UsbEnabled(false))
            ));
        }
        assert!(!desktop.ble_enabled && !desktop.usb_enabled);
        assert!(commands.try_recv().is_err());
    }

    fn painted_widgets(
        output: &egui::FullOutput,
    ) -> (Vec<egui::epaint::TextShape>, Vec<egui::Rect>) {
        fn visit(
            shape: &egui::epaint::Shape,
            text: &mut Vec<egui::epaint::TextShape>,
            rects: &mut Vec<egui::Rect>,
        ) {
            match shape {
                egui::epaint::Shape::Text(shape) => text.push(shape.clone()),
                egui::epaint::Shape::Rect(shape) => rects.push(shape.rect),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        visit(shape, text, rects);
                    }
                }
                _ => {}
            }
        }
        let (mut text, mut rects) = (Vec::new(), Vec::new());
        for shape in &output.shapes {
            visit(&shape.shape, &mut text, &mut rects);
        }
        (text, rects)
    }

    fn desktop_input() -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(570.0, 500.0),
            )),
            ..Default::default()
        }
    }

    #[test]
    fn rendered_listen_address_fonts_are_larger_and_centered() {
        let (mut desktop, _commands, _events) = controller();
        let ctx = egui::Context::default();
        let _ = ctx.run(desktop_input(), |ctx| desktop.show(ctx));
        let output = ctx.run(desktop_input(), |ctx| desktop.show(ctx));
        let (text, _) = painted_widgets(&output);
        for (wanted, size, family) in [
            ("Listen Address", 18.0, egui::FontFamily::Proportional),
            ("127.0.0.1:10233", 28.0, egui::FontFamily::Monospace),
        ] {
            let shape = text
                .iter()
                .find(|shape| shape.galley.text() == wanted)
                .unwrap();
            assert!(!shape.galley.job.sections.is_empty());
            for section in &shape.galley.job.sections {
                assert_eq!(section.format.font_id.size, size, "{wanted}");
                assert_eq!(section.format.font_id.family, family, "{wanted}");
            }
            let bounds = shape.galley.rect.translate(shape.pos.to_vec2());
            assert!(
                (bounds.center().x - 285.0).abs() < 2.0,
                "{wanted}: {bounds:?}"
            );
        }
    }

    #[test]
    fn rendered_approval_footer_is_bottom_right_and_dispatches_the_pending_identity() {
        for (choice, approve) in [("Approve", true), ("Reject", false)] {
            let (mut desktop, commands, _events) = controller();
            desktop.listening = true;
            desktop.pending = Some(PendingApproval {
                id: "current-request-id".into(),
                origin: "https://example.test:8443".into(),
                expires_in: 60,
            });
            let ctx = egui::Context::default();
            let _ = ctx.run(desktop_input(), |ctx| desktop.show(ctx));
            let _ = ctx.run(desktop_input(), |ctx| desktop.show(ctx));
            let output = ctx.run(desktop_input(), |ctx| desktop.show(ctx));
            let (text, rects) = painted_widgets(&output);
            let button_bounds = |label: &str| {
                let shape = text
                    .iter()
                    .find(|shape| shape.galley.text() == label)
                    .unwrap();
                let label = shape.galley.rect.translate(shape.pos.to_vec2());
                *rects
                    .iter()
                    .filter(|rect| rect.contains_rect(label))
                    .min_by(|left, right| left.area().total_cmp(&right.area()))
                    .expect("The button must paint a frame around its label")
            };
            let approve_bounds = button_bounds("Approve");
            let reject_bounds = button_bounds("Reject");
            let window = ctx.memory(|memory| {
                memory
                    .area_rect(egui::Id::new("Approve browser pairing"))
                    .unwrap()
            });
            let margin = egui::Frame::window(&ctx.style()).total_margin();
            assert!(
                approve_bounds.right() < reject_bounds.left(),
                "Choice order changed"
            );
            assert!((approve_bounds.center().y - reject_bounds.center().y).abs() < 0.5);
            assert!(
                (reject_bounds.right() - (window.right() - margin.right)).abs() < 1.0,
                "Footer is not right aligned: {reject_bounds:?}; {window:?}"
            );
            for bounds in [approve_bounds, reject_bounds] {
                assert!(
                    (bounds.bottom() - (window.bottom() - margin.bottom)).abs() < 1.0,
                    "Footer is not bottom aligned: {bounds:?}; {window:?}"
                );
            }
            assert!(
                commands.try_recv().is_err(),
                "Rendering cannot choose an action"
            );
            let position = button_bounds(choice).center();
            for _ in 0..2 {
                for pressed in [true, false] {
                    let _ = ctx.run(
                        egui::RawInput {
                            events: vec![
                                egui::Event::PointerMoved(position),
                                egui::Event::PointerButton {
                                    pos: position,
                                    button: egui::PointerButton::Primary,
                                    pressed,
                                    modifiers: egui::Modifiers::NONE,
                                },
                            ],
                            ..desktop_input()
                        },
                        |ctx| desktop.show(ctx),
                    );
                }
            }
            assert!(
                matches!(commands.try_recv(), Ok(Command::DecidePairing { id, approve: actual })
                if id == "current-request-id" && actual == approve)
            );
            assert!(commands.try_recv().is_err(), "Busy buttons cannot resubmit");
            assert!(desktop.busy);
        }
    }

    #[test]
    fn channel_defaults_and_approval_text_match_enabled_channels() {
        let (desktop, _, _) = controller();
        assert!(desktop.ble_enabled && desktop.usb_enabled);
        assert_eq!(
            approval_question(true, true),
            "Allow pairing, BLE and USB for this origin?"
        );
        assert_eq!(
            approval_question(true, false),
            "Allow pairing and BLE for this origin?"
        );
        assert_eq!(
            approval_question(false, true),
            "Allow pairing and USB for this origin?"
        );
        assert_eq!(
            approval_question(false, false),
            "Allow pairing for this origin?"
        );
        assert_eq!(ble_status(None, false), ("BLE: disabled", false));
    }
    #[test]
    fn physical_usb_open_does_not_claim_transport_connected() {
        let mut status = webauthn_helper::fido_device::Status {
            attached: true,
            message: "USB: waiting for browser transport".into(),
            ..Default::default()
        };
        assert_eq!(
            usb_status(&status, true),
            ("USB: waiting for browser", false)
        );
        status.message = "USB: ready".into();
        assert_eq!(usb_status(&status, true), ("USB: connected", true));
        assert_eq!(usb_status(&status, false), ("USB: stopping", false));
        status.attached = false;
        assert_eq!(usb_status(&status, false), ("USB: disabled", false));
    }

    #[test]
    fn start_stop_controls_listener_and_prevents_duplicate_clicks() {
        let (mut desktop, receiver, events) = controller();
        assert!(!desktop.listening);
        assert!(desktop.usb_enabled);
        assert_eq!(desktop.address, "127.0.0.1:10233");
        desktop.toggle_listener();
        desktop.toggle_listener();
        assert!(matches!(
            receiver.try_recv(),
            Ok(Command::StartListener(10233))
        ));
        assert!(receiver.try_recv().is_err());
        events
            .send(Event::Listening("ws://127.0.0.1:10234".into()))
            .unwrap();
        desktop.receive();
        assert!(desktop.listening);
        assert!(desktop.pending.is_none());
        assert_eq!(desktop.address, "127.0.0.1:10234");
        desktop.toggle_listener();
        assert!(matches!(receiver.try_recv(), Ok(Command::StopListener)));
        events.send(Event::Stopped(Ok(()))).unwrap();
        desktop.receive();
        assert!(!desktop.listening);
        assert!(desktop.pending.is_none());
        assert!(desktop.snapshot.is_none());
        desktop.address = "127.0.0.1:12000".into();
        desktop.toggle_listener();
        assert!(matches!(
            receiver.try_recv(),
            Ok(Command::StartListener(12000))
        ));
    }

    #[test]
    fn invalid_address_never_starts_or_dials() {
        let (mut desktop, receiver, _) = controller();
        desktop.address = "https://backend.example".into();
        desktop.toggle_listener();
        assert!(receiver.try_recv().is_err());
        assert!(!desktop.busy);
        assert!(desktop.error.is_some());
    }

    #[test]
    fn approval_dispatch_contains_only_request_id() {
        let (mut desktop, receiver, _) = controller();
        desktop.command(Command::DecidePairing {
            id: "request-id".into(),
            approve: true,
        });
        assert!(desktop.busy);
        assert!(desktop.error.is_none());
        assert!(matches!(
            receiver.recv().unwrap(),
            Command::DecidePairing { .. }
        ));
    }

    #[test]
    fn unavailable_worker_is_visible() {
        let (mut desktop, receiver, _) = controller();
        drop(receiver);
        desktop.toggle_listener();
        assert!(desktop.fatal);
        assert!(!desktop.busy);
        assert!(desktop.error.as_ref().unwrap().contains("unavailable"));
    }

    #[test]
    fn failed_stop_does_not_claim_stopped_or_allow_restart() {
        let (mut desktop, receiver, events) = controller();
        desktop.listening = true;
        events
            .send(Event::Stopped(Err("OS cleanup failed".into())))
            .unwrap();
        desktop.receive();
        assert!(desktop.listening);
        assert!(desktop.fatal);
        desktop.toggle_listener();
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn close_dispatch_is_idempotent() {
        let (mut desktop, receiver, _) = controller();
        desktop.request_close();
        desktop.request_close();
        assert!(matches!(receiver.try_recv(), Ok(Command::Shutdown)));
        assert!(receiver.try_recv().is_err());
        assert_eq!(desktop.close_state, CloseState::Stopping);
    }

    #[test]
    fn ble_label_does_not_invent_a_device_connection() {
        assert_eq!(ble_status(None, true), ("BLE: stopped", false));
    }

    #[test]
    fn allow_again_dispatch_preserves_exact_origin_and_does_not_approve() {
        let (mut desktop, receiver, events) = controller();
        desktop.command(Command::AllowPairing("https://example.test:8443".into()));
        assert!(
            matches!(receiver.recv().unwrap(), Command::AllowPairing(origin) if origin == "https://example.test:8443")
        );
        assert!(desktop.busy);
        events.send(Event::Allowed).unwrap();
        desktop.receive();
        assert!(!desktop.busy);
        assert!(desktop.pending.is_none());
        assert!(!desktop.listening);
    }
}
