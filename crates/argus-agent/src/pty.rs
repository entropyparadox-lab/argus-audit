use crate::redaction::SecretRedactor;
use argus_common::events::{AuditEvent, KeystrokeInput, SessionEnd, SessionInit};
use nix::pty::{openpty, Winsize};
use nix::sys::select::{select, FdSet};
use nix::sys::signal::{self, SigHandler, Signal};
use nix::sys::termios::{self, SetArg, Termios};
use nix::sys::wait::waitpid;
use nix::unistd::{close, dup2, execvp, fork, read, write, ForkResult, Pid};
use std::ffi::CString;
use std::io::{self, stdout, IsTerminal};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::Instant;
use uuid::Uuid;

static RESIZE_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigwinch(_: i32) {
    RESIZE_FLAG.store(true, Ordering::Relaxed);
}

/// RAII Guard to ensure raw mode on stdin is restored when exiting
struct RawTerminalGuard {
    original_termios: Option<Termios>,
}

impl RawTerminalGuard {
    fn new() -> io::Result<Self> {
        let stdin_fd = io::stdin().as_raw_fd();
        let original_termios = if io::stdin().is_terminal() {
            let termios = termios::tcgetattr(unsafe { BorrowedFd::borrow_raw(stdin_fd) })
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let mut raw = termios.clone();
            termios::cfmakeraw(&mut raw);
            termios::tcsetattr(
                unsafe { BorrowedFd::borrow_raw(stdin_fd) },
                SetArg::TCSANOW,
                &raw,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Some(termios)
        } else {
            None
        };

        Ok(Self { original_termios })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(ref original) = self.original_termios {
            let stdin_fd = io::stdin().as_raw_fd();
            let _ = termios::tcsetattr(
                unsafe { BorrowedFd::borrow_raw(stdin_fd) },
                SetArg::TCSANOW,
                original,
            );
        }
    }
}

pub struct PtyRunner {
    pub session_id: Uuid,
    pub shell: String,
    pub event_tx: Sender<AuditEvent>,
    pub mask_secrets: bool,
}

impl PtyRunner {
    pub fn new(
        session_id: Uuid,
        shell: String,
        event_tx: Sender<AuditEvent>,
        mask_secrets: bool,
    ) -> Self {
        Self {
            session_id,
            shell,
            event_tx,
            mask_secrets,
        }
    }

    /// Run the interactive session wrapper
    pub fn run(self, init_event: SessionInit) -> anyhow::Result<i32> {
        let start_time = Instant::now();
        let _ = self.event_tx.send(AuditEvent::SessionInit(init_event));

        // Get window size from stdout if available
        let winsize = if stdout().is_terminal() {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            unsafe {
                libc::ioctl(stdout().as_raw_fd(), libc::TIOCGWINSZ as _, &mut ws);
            }
            Some(Winsize {
                ws_row: ws.ws_row,
                ws_col: ws.ws_col,
                ws_xpixel: ws.ws_xpixel,
                ws_ypixel: ws.ws_ypixel,
            })
        } else {
            None
        };

        let pty_pair = openpty(winsize.as_ref(), None)?;
        let master_fd = pty_pair.master.as_raw_fd();
        let slave_fd = pty_pair.slave.as_raw_fd();

        match unsafe { fork()? } {
            ForkResult::Child => {
                // Child: set up new session and dup slave to std fds
                unsafe {
                    libc::setsid();
                    libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0);
                }

                dup2(slave_fd, libc::STDIN_FILENO)?;
                dup2(slave_fd, libc::STDOUT_FILENO)?;
                dup2(slave_fd, libc::STDERR_FILENO)?;

                let _ = close(master_fd);
                let _ = close(slave_fd);

                let shell_c = CString::new(self.shell.as_str())?;
                let args = [shell_c.clone()];
                let _ = execvp(&shell_c, &args);
                std::process::exit(1);
            }
            ForkResult::Parent { child } => {
                let _ = close(slave_fd);
                let _raw_guard = RawTerminalGuard::new()?;

                // Register SIGWINCH handler
                unsafe {
                    signal::signal(Signal::SIGWINCH, SigHandler::Handler(handle_sigwinch))?;
                }

                let exit_status = self.event_loop(master_fd, child, start_time)?;
                Ok(exit_status)
            }
        }
    }

    fn event_loop(&self, master_fd: RawFd, child: Pid, start_time: Instant) -> anyhow::Result<i32> {
        let stdin_fd = io::stdin().as_raw_fd();
        let stdout_fd = io::stdout().as_raw_fd();
        let mut in_seq = 0u64;
        let mut total_bytes = 0u64;
        let mut in_buf = [0u8; 4096];
        let mut out_buf = [0u8; 16384];

        loop {
            // Check for window resize
            if RESIZE_FLAG.swap(false, Ordering::Relaxed) && stdout().is_terminal() {
                let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                unsafe {
                    if libc::ioctl(stdout_fd, libc::TIOCGWINSZ as _, &mut ws) == 0 {
                        libc::ioctl(master_fd, libc::TIOCSWINSZ as _, &ws);
                    }
                }
            }

            let mut read_fds = FdSet::new();
            read_fds.insert(unsafe { BorrowedFd::borrow_raw(stdin_fd) });
            read_fds.insert(unsafe { BorrowedFd::borrow_raw(master_fd) });

            let max_fd = master_fd.max(stdin_fd);

            match select(max_fd + 1, Some(&mut read_fds), None, None, None) {
                Ok(_) => {
                    // 1. User typed or pasted on stdin -> Record as Input event & forward to child
                    if read_fds.contains(unsafe { BorrowedFd::borrow_raw(stdin_fd) }) {
                        match read(stdin_fd, &mut in_buf) {
                            Ok(0) => break, // EOF on stdin
                            Ok(n) => {
                                let elapsed = start_time.elapsed().as_millis() as u64;
                                let raw_slice = in_buf[..n].to_vec();
                                let is_paste = n > 16 || raw_slice.starts_with(b"\x1b[200~");

                                in_seq += 1;
                                total_bytes += n as u64;

                                // Redact in-flight secrets before queuing event if enabled
                                let recorded_slice = if self.mask_secrets {
                                    SecretRedactor::redact_bytes(&raw_slice)
                                } else {
                                    raw_slice.clone()
                                };

                                let event = KeystrokeInput::new(
                                    self.session_id,
                                    in_seq,
                                    elapsed,
                                    recorded_slice,
                                    is_paste,
                                );
                                let _ = self.event_tx.send(AuditEvent::KeystrokeInput(event));

                                // Forward original stdin directly to child PTY master (unaltered execution)
                                let _ =
                                    write(unsafe { BorrowedFd::borrow_raw(master_fd) }, &raw_slice);
                            }
                            Err(_) => break,
                        }
                    }

                    // 2. Child PTY output -> Pass through to user screen WITHOUT logging (Input-Only Optimization)
                    if read_fds.contains(unsafe { BorrowedFd::borrow_raw(master_fd) }) {
                        match read(master_fd, &mut out_buf) {
                            Ok(0) => break, // Child closed stdout/stderr
                            Ok(n) => {
                                let _ = write(
                                    unsafe { BorrowedFd::borrow_raw(stdout_fd) },
                                    &out_buf[..n],
                                );
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => break,
            }
        }

        // Wait for child process exit
        let exit_code = match waitpid(child, None) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => Some(code),
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => Some(128 + sig as i32),
            _ => None,
        };

        // Send SessionEnd event
        let end_event = SessionEnd {
            session_id: self.session_id,
            timestamp: chrono::Utc::now(),
            duration_ms: start_time.elapsed().as_millis() as u64,
            total_input_bytes: total_bytes,
            exit_status: exit_code,
        };
        let _ = self.event_tx.send(AuditEvent::SessionEnd(end_event));

        Ok(exit_code.unwrap_or(0))
    }
}
