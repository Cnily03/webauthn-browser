#[cfg(test)]
use std::io::Write;
// The input worker owns prompt publication and nonblocking input acquisition.
// Buffered input can never be relabeled by a concurrent UI update.
use std::{
    io,
    sync::mpsc::{Receiver, TryRecvError},
    time::Duration,
};
use tokio::sync::mpsc::Sender;

pub enum Control {
    Prompt { id: String, origin: String },
    Clear,
}
pub struct InputLine {
    pub text: String,
    pub prompt_id: Option<String>,
}
pub enum ReadResult {
    Pending,
    Data(Vec<u8>),
    Eof,
}
pub trait InputSource {
    fn read_available(&mut self, timeout: Duration) -> io::Result<ReadResult>;
    fn discard_terminal_input(&mut self) -> io::Result<()>;
}
#[derive(Default)]
struct Lines {
    bytes: Vec<u8>,
    generation: Option<String>,
}
impl Lines {
    fn accept(
        &mut self,
        bytes: &[u8],
        generation: &Option<String>,
        send: &Sender<InputLine>,
    ) -> io::Result<bool> {
        for byte in bytes {
            if self.bytes.is_empty() {
                self.generation = generation.clone();
            }
            match *byte {
                b'\n' => {
                    let line = InputLine {
                        text: String::from_utf8_lossy(&self.bytes).into_owned(),
                        prompt_id: self.generation.take(),
                    };
                    self.bytes.clear();
                    if send.blocking_send(line).is_err() {
                        return Ok(false);
                    }
                }
                8 | 127 => {
                    self.bytes.pop();
                }
                _ => {
                    if self.bytes.len() >= 4096 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Terminal input line too long",
                        ));
                    }
                    self.bytes.push(*byte);
                }
            }
        }
        Ok(true)
    }
}
fn drain_old_input(source: &mut impl InputSource, send: &Sender<InputLine>) -> io::Result<bool> {
    let mut old_input = Lines::default();
    for _ in 0..64 {
        match source.read_available(Duration::ZERO)? {
            ReadResult::Pending => {
                // Read complete commands before discarding an unfinished terminal line.
                source.discard_terminal_input()?;
                return Ok(true);
            }
            ReadResult::Eof => return Ok(false),
            ReadResult::Data(bytes) => {
                // Preserve queued commands, but no old answer can acquire this prompt.
                if !old_input.accept(&bytes, &None, send)? {
                    return Ok(false);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Input keeps arriving before confirmation; closing safely",
    ))
}
#[cfg(test)]
fn publish(
    source: &mut impl InputSource,
    output: &mut impl Write,
    lines: &mut Lines,
    generation: &mut Option<String>,
    id: String,
    message: &str,
    send: &Sender<InputLine>,
) -> io::Result<bool> {
    // This worker owns stdin and the entire visibility transition. Also drain
    // after flush: terminal output may block while old input continues arriving.
    *lines = Lines::default();
    if !drain_old_input(source, send)? {
        return Ok(false);
    }
    output.write_all(format!("{message}\n").as_bytes())?;
    output.flush()?;
    if !drain_old_input(source, send)? {
        return Ok(false);
    }
    *generation = Some(id);
    Ok(true)
}

fn discard_events() -> io::Result<()> {
    for _ in 0..256 {
        if !crossterm::event::poll(Duration::ZERO)? {
            return Ok(());
        }
        let _ = crossterm::event::read()?;
    }
    Err(io::Error::other(
        "Input keeps arriving before confirmation; closing safely",
    ))
}

pub fn run(
    mut source: impl InputSource,
    controls: Receiver<Control>,
    send: Sender<InputLine>,
) -> io::Result<()> {
    use super::terminal_ui;
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    let _restore = terminal_ui::Restore;
    let mut lines = Lines::default();
    loop {
        loop {
            match controls.try_recv() {
                Ok(Control::Prompt { id, origin }) => {
                    lines = Lines::default();
                    if !terminal_ui::interactive() {
                        tracing::warn!("Cannot approve Origin {} without an interactive terminal; rejecting this request.", origin);
                        if send
                            .blocking_send(InputLine {
                                text: "reject".into(),
                                prompt_id: Some(id),
                            })
                            .is_err()
                        {
                            return Ok(());
                        }
                        continue;
                    }
                    if !drain_old_input(&mut source, &send)? {
                        return Ok(());
                    }
                    terminal_ui::show(id, origin)?;
                    // Input acquired before/during publication cannot authorize this panel.
                    discard_events()?;
                    source.discard_terminal_input()?;
                }
                Ok(Control::Clear) => {
                    terminal_ui::clear()?;
                    lines = Lines::default();
                    source.discard_terminal_input()?;
                }
                Err(TryRecvError::Disconnected) => return Ok(()),
                Err(TryRecvError::Empty) => break,
            }
        }
        if let Some((id, approve)) = terminal_ui::selection() {
            if !event::poll(Duration::from_millis(25))? {
                continue;
            }
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Left => terminal_ui::select(Some(true))?,
                    KeyCode::Right => terminal_ui::select(Some(false))?,
                    KeyCode::Tab | KeyCode::BackTab => terminal_ui::select(None)?,
                    KeyCode::Enter => {
                        // Drain the entire old input burst before a new candidate can appear.
                        discard_events()?;
                        source.discard_terminal_input()?;
                        terminal_ui::clear()?;
                        if send
                            .blocking_send(InputLine {
                                text: if approve { "approve" } else { "reject" }.into(),
                                prompt_id: Some(id),
                            })
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    KeyCode::Char('c' | 'd' | 'z')
                        if key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        return Ok(())
                    }
                    _ => {}
                },
                Event::Resize(_, _) => terminal_ui::select(Some(approve))?,
                // Pasted text is never a confirmation action.
                _ => {}
            }
        } else {
            match source.read_available(Duration::from_millis(25))? {
                ReadResult::Pending => {}
                ReadResult::Eof => return Ok(()),
                ReadResult::Data(bytes) => {
                    if !lines.accept(&bytes, &None, &send)? {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
pub struct StdinSource;
#[cfg(unix)]
impl InputSource for StdinSource {
    fn read_available(&mut self, timeout: Duration) -> io::Result<ReadResult> {
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // Safety: one valid pollfd, no competing stdin readers; poll bounds waiting.
        let ready = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                timeout.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(ReadResult::Pending)
            } else {
                Err(error)
            };
        }
        if ready == 0 {
            return Ok(ReadResult::Pending);
        }
        let mut buffer = [0u8; 1024];
        // Safety: buffer is valid; poll reported data or EOF and this is the only reader.
        let count =
            unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            return Ok(ReadResult::Eof);
        }
        Ok(ReadResult::Data(buffer[..count as usize].to_vec()))
    }
    fn discard_terminal_input(&mut self) -> io::Result<()> {
        // Canonical terminals can retain a partial prefilled answer until Enter.
        // Safety: tcflush operates only on our stdin, never changes terminal modes.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1
            && unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct StdinSource;
#[cfg(windows)]
impl InputSource for StdinSource {
    fn read_available(&mut self, timeout: Duration) -> io::Result<ReadResult> {
        use windows_sys::Win32::{
            Foundation::ERROR_BROKEN_PIPE,
            Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_PIPE},
            System::{
                Console::{
                    GetConsoleMode, GetNumberOfConsoleInputEvents, GetStdHandle, ReadConsoleInputW,
                    INPUT_RECORD, KEY_EVENT, STD_INPUT_HANDLE,
                },
                Pipes::PeekNamedPipe,
            },
        };
        // Safety: Win32 receives valid local out-parameters and the process's stdin handle.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                let mut count = 0;
                if GetNumberOfConsoleInputEvents(handle, &mut count) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if count == 0 {
                    std::thread::sleep(timeout);
                    return Ok(ReadResult::Pending);
                }
                let mut event: INPUT_RECORD = std::mem::zeroed();
                if ReadConsoleInputW(handle, &mut event, 1, &mut count) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if event.EventType != KEY_EVENT as u16 {
                    return Ok(ReadResult::Data(vec![]));
                }
                let key = event.Event.KeyEvent;
                if key.bKeyDown == 0 {
                    return Ok(ReadResult::Data(vec![]));
                }
                let character = key.uChar.UnicodeChar;
                if character == 26 {
                    return Ok(ReadResult::Eof);
                }
                let Some(character) = char::from_u32(character as u32).filter(|c| *c != '\0')
                else {
                    return Ok(ReadResult::Data(vec![]));
                };
                let character = if character == '\r' { '\n' } else { character };
                let mut encoded = [0; 4];
                return Ok(ReadResult::Data(
                    character.encode_utf8(&mut encoded).as_bytes().to_vec(),
                ));
            }
            if GetFileType(handle) == FILE_TYPE_PIPE {
                let mut available = 0;
                if PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                ) == 0
                {
                    let error = io::Error::last_os_error();
                    return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                        Ok(ReadResult::Eof)
                    } else {
                        Err(error)
                    };
                }
                if available == 0 {
                    std::thread::sleep(timeout);
                    return Ok(ReadResult::Pending);
                }
            }
            let mut bytes = [0; 1024];
            let mut count = 0;
            if ReadFile(
                handle,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut count,
                std::ptr::null_mut(),
            ) == 0
            {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    Ok(ReadResult::Eof)
                } else {
                    Err(error)
                };
            }
            if count == 0 {
                Ok(ReadResult::Eof)
            } else {
                Ok(ReadResult::Data(bytes[..count as usize].to_vec()))
            }
        }
    }
    fn discard_terminal_input(&mut self) -> io::Result<()> {
        use windows_sys::Win32::System::Console::{
            FlushConsoleInputBuffer, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
        };
        // Safety: checks console mode before flushing this process's own input queue.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) != 0 && FlushConsoleInputBuffer(handle) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    struct Source {
        reads: Rc<RefCell<VecDeque<ReadResult>>>,
        flushed: bool,
    }
    impl InputSource for Source {
        fn read_available(&mut self, _: Duration) -> io::Result<ReadResult> {
            Ok(self
                .reads
                .borrow_mut()
                .pop_front()
                .unwrap_or(ReadResult::Pending))
        }
        fn discard_terminal_input(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }
    struct Output {
        bytes: Vec<u8>,
        reads: Rc<RefCell<VecDeque<ReadResult>>>,
        fail_flush: bool,
    }
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::other("flush failed"));
            }
            // An Enter arrives while output flush is still in progress.
            self.reads
                .borrow_mut()
                .push_back(ReadResult::Data(b"\n".to_vec()));
            Ok(())
        }
    }
    #[test]
    fn input_before_or_during_show_is_unbound_but_first_fresh_enter_is_bound() {
        let reads = Rc::new(RefCell::new(VecDeque::from([
            ReadResult::Data(b"status\nyes\n\n".to_vec()),
            ReadResult::Pending,
        ])));
        let mut source = Source {
            reads: reads.clone(),
            flushed: false,
        };
        let mut output = Output {
            bytes: vec![],
            reads,
            fail_flush: false,
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut lines = Lines {
            bytes: b"prefilled-y".to_vec(),
            generation: Some("old".into()),
        };
        let mut generation = Some("old".into());
        assert!(publish(
            &mut source,
            &mut output,
            &mut lines,
            &mut generation,
            "new".into(),
            "Origin https://example.com [Y/n]",
            &tx
        )
        .unwrap());
        assert!(source.flushed);
        assert_eq!(generation.as_deref(), Some("new"));
        for expected in ["status", "yes", "", ""] {
            let old = rx.try_recv().unwrap();
            assert_eq!(old.text, expected);
            assert!(old.prompt_id.is_none());
        }
        source
            .reads
            .borrow_mut()
            .push_back(ReadResult::Data(b"\n".to_vec()));
        let ReadResult::Data(fresh) = source.read_available(Duration::ZERO).unwrap() else {
            panic!("fresh Enter")
        };
        lines.accept(&fresh, &generation, &tx).unwrap();
        let fresh = rx.try_recv().unwrap();
        assert_eq!(fresh.text, "");
        assert_eq!(fresh.prompt_id.as_deref(), Some("new"));
    }
    #[test]
    fn failed_prompt_flush_never_publishes_new_generation() {
        let reads = Rc::new(RefCell::new(VecDeque::from([ReadResult::Pending])));
        let mut source = Source {
            reads: reads.clone(),
            flushed: false,
        };
        let mut output = Output {
            bytes: vec![],
            reads,
            fail_flush: true,
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut generation = None;
        assert!(publish(
            &mut source,
            &mut output,
            &mut Lines::default(),
            &mut generation,
            "new".into(),
            "[Y/n]",
            &tx
        )
        .is_err());
        assert!(generation.is_none());
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn eof_discards_partial_yes_instead_of_creating_default_consent() {
        for input in [b"".as_slice(), b"y", b"yes", b" "] {
            let reads = Rc::new(RefCell::new(VecDeque::from([
                ReadResult::Data(input.to_vec()),
                ReadResult::Eof,
            ])));
            let source = Source {
                reads,
                flushed: false,
            };
            let (_controls, control_rx) = std::sync::mpsc::channel();
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            run(source, control_rx, tx).unwrap();
            assert!(rx.try_recv().is_err());
        }
    }
    #[test]
    fn one_read_burst_keeps_one_generation_for_all_answers() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        Lines::default()
            .accept(b"\n\n", &Some("old".into()), &tx)
            .unwrap();
        assert_eq!(rx.try_recv().unwrap().prompt_id.as_deref(), Some("old"));
        assert_eq!(rx.try_recv().unwrap().prompt_id.as_deref(), Some("old"));
    }
}
