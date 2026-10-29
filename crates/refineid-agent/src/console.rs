//! The agent's console: Ctrl+C, Ctrl+Break and closing the agent's console
//! window are its user quitting it (RAPP v26.10.29 section 4.5 item 8).
//! Log-off and shutdown keep the default handling: the operating system
//! ending the agent is not a withdrawal.

#![expect(unsafe_code, reason = "the console control handler boundary")]

use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{FALSE, GetLastError, TRUE};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler,
};
use windows_sys::core::BOOL;

/// The exit status of an agent its user quit: a deliberate stop.
const QUIT_EXIT_STATUS: i32 = 0;

/// What the agent does when its user quits it, before it exits.
static ON_QUIT: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Runs `on_quit` and then exits when the user quits the agent from its
/// console. Windows calls it on a thread of its own; for a closed window it
/// ends the process a few seconds later regardless. Only the first call
/// installs an action.
///
/// # Errors
/// The Windows error when the handler is refused.
pub fn on_quit(on_quit: impl Fn() + Send + Sync + 'static) -> Result<(), u32> {
    if ON_QUIT.set(Box::new(on_quit)).is_err() {
        return Ok(());
    }
    // SAFETY: `console_event` has the `HandlerRoutine` signature and lives
    // as long as the process.
    if unsafe { SetConsoleCtrlHandler(Some(console_event), TRUE) } == FALSE {
        // SAFETY: no arguments; read right after the call it describes.
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// The console control handler: a quit runs the agent's action and exits;
/// every other event goes on to the default handling.
unsafe extern "system" fn console_event(event: u32) -> BOOL {
    match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT => {
            if let Some(on_quit) = ON_QUIT.get() {
                on_quit();
            }
            std::process::exit(QUIT_EXIT_STATUS)
        }
        _ => FALSE,
    }
}
