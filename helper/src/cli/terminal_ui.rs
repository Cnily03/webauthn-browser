//! A single inline confirmation panel and serialized log output; never a full-screen UI.
use crossterm::{
    cursor, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType},
};
use std::{
    io::{self, IsTerminal, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex,
    },
};

#[derive(Clone)]
struct Panel {
    id: String,
    origin: String,
    approve: bool,
}
#[derive(Default)]
struct Display {
    panel: Option<Panel>,
    rows: u16,
    raw: bool,
}
static PANEL_ACTIVE: AtomicBool = AtomicBool::new(false);
static DISPLAY: LazyLock<Mutex<Display>> = LazyLock::new(|| Mutex::new(Display::default()));
fn display() -> std::sync::MutexGuard<'static, Display> {
    DISPLAY.lock().unwrap_or_else(|e| e.into_inner())
}
pub(super) fn interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}
// A duplicated handle avoids holding Rust's global stdout mutex across a blocked
// OS write. Terminal output may stall; process shutdown must still be possible.
#[cfg(unix)]
fn output() -> io::Result<std::fs::File> {
    use std::os::fd::AsFd;
    io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map(std::fs::File::from)
}
#[cfg(windows)]
struct Output {
    file: std::fs::File,
    console: bool,
}
#[cfg(windows)]
fn output() -> io::Result<Output> {
    use std::os::windows::io::{AsHandle, AsRawHandle};
    let file = std::fs::File::from(io::stdout().as_handle().try_clone_to_owned()?);
    let mut mode = 0;
    // Match std::io's Unicode console behavior without its global stdout lock.
    // Microsoft requires WriteConsoleW for consoles and WriteFile for redirected
    // handles; no console code page or host policy is changed.
    let console = unsafe {
        windows_sys::Win32::System::Console::GetConsoleMode(file.as_raw_handle(), &mut mode) != 0
    };
    Ok(Output { file, console })
}
#[cfg(windows)]
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use std::os::windows::io::AsRawHandle;
        if !self.console {
            return self.file.write(bytes);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let wide: Vec<u16> = text.encode_utf16().collect();
        let mut offset = 0;
        while offset < wide.len() {
            let mut written = 0;
            let count = (wide.len() - offset).min(8192) as u32;
            let result = unsafe {
                windows_sys::Win32::System::Console::WriteConsoleW(
                    self.file.as_raw_handle(),
                    wide[offset..].as_ptr(),
                    count,
                    &mut written,
                    std::ptr::null(),
                )
            };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            offset += written as usize;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn colors() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn erase(state: &mut Display, out: &mut impl Write) -> io::Result<()> {
    if state.rows == 0 {
        return Ok(());
    }
    queue!(out, cursor::MoveToColumn(0), cursor::MoveUp(state.rows))?;
    for line in 0..state.rows {
        queue!(out, Clear(ClearType::CurrentLine))?;
        if line + 1 < state.rows {
            queue!(out, cursor::MoveDown(1))?;
        }
    }
    if state.rows > 1 {
        queue!(out, cursor::MoveUp(state.rows - 1))?;
    }
    queue!(out, cursor::MoveToColumn(0))?;
    state.rows = 0;
    Ok(())
}
fn border(out: &mut impl Write, text: &str) -> io::Result<()> {
    if colors() {
        queue!(out, SetForegroundColor(Color::Magenta))?;
    }
    queue!(out, Print(text))?;
    if colors() {
        queue!(out, ResetColor)?;
    }
    Ok(())
}
fn draw(state: &mut Display, out: &mut impl Write) -> io::Result<()> {
    let Some(panel) = &state.panel else {
        return Ok(());
    };
    let (columns, rows) = terminal::size()?;
    if columns < 40 || rows < 8 {
        return Err(io::Error::other(
            "Terminal is too small for a safe origin confirmation",
        ));
    }
    let width = usize::from(columns.saturating_sub(4)).min(88);
    let content_width = width - 2;
    let mut lines = Vec::new();
    for text in [
        format!("Browser Origin: {}", panel.origin),
        approval_question(
            BLE_ENABLED.load(std::sync::atomic::Ordering::Relaxed),
            USB_ENABLED.load(std::sync::atomic::Ordering::Relaxed),
        )
        .into(),
    ] {
        let chars: Vec<char> = text.chars().collect();
        for chunk in chars.chunks(content_width) {
            lines.push(chunk.iter().collect::<String>());
        }
    }
    lines.push(
        if panel.approve {
            "> [ Approve ]    [ Reject ]"
        } else {
            "  [ Approve ]  > [ Reject ]"
        }
        .into(),
    );
    lines.push("Left/Right or Tab, then Enter".into());
    if lines.len() + 3 > rows as usize {
        return Err(io::Error::other(
            "Terminal is too short to show the complete origin",
        ));
    }
    border(out, &format!("┌{}┐", "─".repeat(width)))?;
    queue!(out, Print("\r\n"))?;
    for (index, line) in lines.iter().enumerate() {
        border(out, "│")?;
        let is_choice = index + 2 == lines.len();
        if is_choice && colors() {
            queue!(out, SetAttribute(Attribute::Bold))?;
        }
        if is_choice {
            let selected = if panel.approve {
                "> [ Approve ]"
            } else {
                "> [ Reject ]"
            };
            let (before, after) = line
                .split_once(selected)
                .expect("choice contains selection");
            queue!(out, Print(format!(" {before}")))?;
            if colors() {
                queue!(out, SetForegroundColor(Color::Cyan))?;
            }
            queue!(out, Print(selected))?;
            if colors() {
                queue!(out, ResetColor)?;
            }
            queue!(
                out,
                Print(format!(
                    "{after}{} ",
                    " ".repeat(content_width.saturating_sub(line.len()))
                ))
            )?;
        } else {
            queue!(out, Print(format!(" {line:content_width$} ")))?;
        }
        if is_choice && colors() {
            queue!(out, SetAttribute(Attribute::Reset))?;
        }
        border(out, "│")?;
        queue!(out, Print("\r\n"))?;
    }
    border(out, &format!("└{}┘", "─".repeat(width)))?;
    queue!(out, Print("\r\n"))?;
    state.rows = (lines.len() + 2) as u16;
    out.flush()
}
pub(super) fn show(id: String, origin: String) -> io::Result<()> {
    if !interactive() {
        return Err(io::Error::other(
            "Approval requires an interactive terminal",
        ));
    }
    PANEL_ACTIVE.store(true, Ordering::Release);
    let mut state = display();
    let mut out = output()?;
    erase(&mut state, &mut out)?;
    terminal::enable_raw_mode()?;
    state.raw = true;
    queue!(out, cursor::Hide, crossterm::event::EnableBracketedPaste)?;
    state.panel = Some(Panel {
        id,
        origin,
        approve: true,
    });
    draw(&mut state, &mut out)
}
pub(super) fn selection() -> Option<(String, bool)> {
    if !PANEL_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    display().panel.as_ref().map(|p| (p.id.clone(), p.approve))
}
pub(super) fn select(approve: Option<bool>) -> io::Result<()> {
    let mut state = display();
    if let Some(panel) = &mut state.panel {
        panel.approve = approve.unwrap_or(!panel.approve);
    }
    let mut out = output()?;
    erase(&mut state, &mut out)?;
    draw(&mut state, &mut out)
}
pub(super) fn clear() -> io::Result<()> {
    if !PANEL_ACTIVE.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut state = display();
    if state.panel.is_none() && state.rows == 0 && !state.raw {
        PANEL_ACTIVE.store(false, Ordering::Release);
        return Ok(());
    }
    let mut out = output()?;
    let erase_result = erase(&mut state, &mut out);
    state.panel = None;
    if state.raw {
        state.raw = false;
        terminal::disable_raw_mode()?;
        queue!(out, cursor::Show, crossterm::event::DisableBracketedPaste)?;
    }
    out.flush()?;
    PANEL_ACTIVE.store(false, Ordering::Release);
    erase_result
}
pub(super) struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        finish();
    }
}
pub(super) fn install_panic_cleanup() {
    let old = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Never wait for a rendering mutex held by the panicking thread, or
        // synchronously write to a terminal that has stopped accepting output.
        cleanup_bounded();
        old(info);
    }));
}
// Only tracing-appender's dedicated thread writes ordinary log records here.
// Rendering stays serialized with the request-bound consent panel.
pub(super) struct RenderWriter;
impl Write for RenderWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = display();
        let mut out = output()?;
        erase(&mut state, &mut out)?;
        if state.raw {
            for part in bytes.split_inclusive(|byte| *byte == b'\n') {
                if let Some(body) = part.strip_suffix(b"\n") {
                    out.write_all(body)?;
                    out.write_all(b"\r\n")?;
                } else {
                    out.write_all(part)?;
                }
            }
        } else {
            out.write_all(bytes)?;
        }
        draw(&mut state, &mut out)?;
        out.flush()?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn write_text(text: &str) -> io::Result<()> {
    super::logging::write_text(text)
}

static FINISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Exit must remain bounded even when the terminal stops accepting output.
/// The panel stays out of the lossy log queue; no queue outcome can approve it.
pub(super) fn finish() {
    if FINISHED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    cleanup_bounded();
}
fn cleanup_bounded() {
    let (done, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = clear();
        let _ = done.send(());
    });
    let _ = wait.recv_timeout(std::time::Duration::from_millis(200));
    // Termios/console input restoration does not wait for terminal log output.
    let _ = terminal::disable_raw_mode();
}

static USB_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static BLE_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
pub(super) fn set_channels(ble: bool, usb: bool) {
    BLE_ENABLED.store(ble, std::sync::atomic::Ordering::Relaxed);
    USB_ENABLED.store(usb, std::sync::atomic::Ordering::Relaxed);
}
fn approval_question(ble: bool, usb: bool) -> &'static str {
    match (ble, usb) {
        (true, true) => "Approve pairing, BLE and USB for this origin?",
        (true, false) => "Approve pairing and BLE for this origin?",
        (false, true) => "Approve pairing and USB for this origin?",
        (false, false) => "Approve pairing for this origin?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_question_lists_only_enabled_channels() {
        assert_eq!(
            approval_question(true, true),
            "Approve pairing, BLE and USB for this origin?"
        );
        assert_eq!(
            approval_question(true, false),
            "Approve pairing and BLE for this origin?"
        );
        assert_eq!(
            approval_question(false, true),
            "Approve pairing and USB for this origin?"
        );
        assert_eq!(
            approval_question(false, false),
            "Approve pairing for this origin?"
        );
    }
    #[test]
    fn inactive_panel_paths_do_not_wait_for_rendering() {
        let _locked = display();
        assert!(!PANEL_ACTIVE.load(Ordering::Acquire));
        assert!(selection().is_none());
        clear().unwrap();
    }
    #[test]
    fn panic_cleanup_never_reenters_a_held_display_mutex() {
        install_panic_cleanup();
        let result = std::panic::catch_unwind(|| {
            let _locked = display();
            panic!("deliberate cleanup regression test");
        });
        assert!(result.is_err());
        // Poison recovery leaves the display usable and no raw terminal owned.
        assert!(!display().raw);
    }
}
