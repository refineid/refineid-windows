// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Win32 implementation behind the crate root's platform dispatch.
//! See `main.rs`: this module only compiles for the Windows target.

use crate::{card, identity, pin, version};
use std::cell::RefCell;
use std::os::windows::ffi::OsStrExt as _;
use std::sync::Mutex;
use zeroize::Zeroize;

use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    COLOR_BTNFACE, COLOR_WINDOW, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontIndirectW,
    CreateFontW, CreateSolidBrush, DEFAULT_CHARSET, DEFAULT_QUALITY, DeleteDC, DeleteObject,
    FONT_CLIP_PRECISION, FONT_OUTPUT_PRECISION, FillRect, GetDC, GetSysColorBrush, HBITMAP, HBRUSH,
    HDC, HFONT, HGDIOBJ, ReleaseDC, SelectObject, SetBkColor, SetTextColor,
};
use windows::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromFile, GdipCreateFromHDC, GdipDeleteGraphics, GdipDisposeImage,
    GdipDrawImageRectI, GdipGetImageDimension, GdipGraphicsClear, GdiplusShutdown, GdiplusStartup,
    GdiplusStartupInput, GpBitmap, GpGraphics, GpImage,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::{SS_BITMAP, SS_CENTER};
use windows::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, NMHDR,
    TAB_CONTROL_ITEM_STATE, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT, TCM_GETCURSEL, TCM_INSERTITEMW,
    TCM_SETCURSEL, TCN_SELCHANGE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, BS_PUSHBUTTON, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, CBN_SELCHANGE,
    CBS_DROPDOWNLIST, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, ES_AUTOVSCROLL, ES_MULTILINE, ES_PASSWORD, ES_READONLY, GetClientRect,
    GetMessageW, HICON, HMENU, IDC_ARROW, IDYES, IMAGE_BITMAP, IsWindow, LB_ADDSTRING,
    LB_GETCURSEL, LB_GETTEXT, LB_GETTEXTLEN, LB_RESETCONTENT, LBN_SELCHANGE, LBS_NOTIFY,
    LoadCursorW, MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_YESNO, MSG,
    MessageBoxW, MoveWindow, NONCLIENTMETRICSW, PostQuitMessage, RegisterClassW, SBS_SIZEGRIP,
    SPI_GETNONCLIENTMETRICS, STM_SETIMAGE, SW_HIDE, SW_SHOW, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    SendMessageW, SetTimer, ShowWindow, SystemParametersInfoW, TranslateMessage, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_COMMAND, WM_CREATE, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DESTROY,
    WM_ERASEBKGND, WM_GETTEXT, WM_GETTEXTLENGTH, WM_NOTIFY, WM_SETFONT, WM_SETTEXT, WM_SIZE,
    WM_TIMER, WNDCLASS_STYLES, WNDCLASSW, WS_BORDER, WS_CHILD, WS_CLIPSIBLINGS,
    WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

use refineid_doc_sign::asic_verify::verify_document;
use refineid_doc_sign::cades::SigningTime;
use refineid_doc_sign::document::Format;
use refineid_doc_sign::pades::SignatureMetadata;
use refineid_doc_sign::service::{
    DocumentRequest, SignOptions, SignReport, SignSlot, sign_with_slot,
};
use refineid_lib_core::identity::CommonName;
use refineid_lib_core::pin::PinBytes;
use refineid_lib_pcsc::PcscBackend;
use refineid_rapp_core::engine::{PairingError, Requester, RequesterConfig};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::limits::OFFER_TTL_MS;
use refineid_rapp_core::offer::normalize_pairing_code;
use refineid_rapp_core::store::{MemoryJournal, PairingStore as _};
use refineid_rapp_core::stream::StreamRendezvous;
use refineid_rapp_core::transport::FrameTransport;
use refineid_windows_credential_store::CredentialPairingStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const TIMER_REFRESH: usize = 1;
const REFRESH_MS: u32 = 2000;
const ATR_POLL_MS: u128 = 30_000;

const IDC_TAB: u16 = 10;
const IDC_STATUSBAR: u16 = 11;
const IDC_READERS: u16 = 101;
const IDC_REFRESH: u16 = 102;
const IDC_SVERSION: u16 = 103;
const IDC_IREAD: u16 = 111;
const IDC_ICAN: u16 = 113;
const IDC_IPHOTO: u16 = 114;
const IDC_ICANLABEL: u16 = 115;
const IDC_PMODE: u16 = 122;
const IDC_PLAB1: u16 = 123;
const IDC_PF1: u16 = 128;
const IDC_PEXEC: u16 = 133;
const IDC_PRESULT: u16 = 134;
const IDC_PREFRESH: u16 = 135;

const TABS: [&str; 5] = ["Status", "Identity", "PIN", "Document", "Remote"];
const STATUSBAR_HEIGHT: i32 = 24;

// Brand palette from the Android companion (`ReFineIdTheme`).
// COLORREF packs as 0x00BBGGRR.
const BG_PAGE: u32 = 0x00FC_F9F7; // #F7F9FC page background
const INK: u32 = 0x0022_1C17; // #171C22 primary text
const GRAY: u32 = 0x0054_4A42; // #424A54 secondary text
const PRIMARY: u32 = 0x00A6_5600; // #0056A6 brand blue
const SUCCESS: u32 = 0x0047_8416; // #168447 status green
const WARNING: u32 = 0x0000_84E1; // #E18400 status amber
const ERROR: u32 = 0x001A_1ABA; // #BA1A1A status red
const WHITE: u32 = 0x00FF_FFFF;

const IDC_HEAD: u16 = 400;
const IDC_SUBHEAD: u16 = 410;
const IDC_IROW: u16 = 500;
const IDC_ILABEL: u16 = 520;
const IDC_ISTATUS: u16 = 540;
const IDC_PHOTO: u16 = 541;
const IDC_PHOTOCAP: u16 = 542;
const IDC_PROW: u16 = 550;
const IDC_PROWLAB: u16 = 560;
const IDC_PSTATUSMSG: u16 = 570;
const IDC_DROWLAB: u16 = 571;
const IDC_DROW: u16 = 573;
const IDC_DBROWSE: u16 = 601;
const IDC_DSIGN: u16 = 602;
const IDC_DFILE: u16 = 603;
const IDC_DFORMAT: u16 = 604;
const IDC_DSLOT: u16 = 605;
const IDC_DPIN: u16 = 606;
const IDC_DREASON: u16 = 607;
const IDC_DRESULT: u16 = 608;
const IDC_VBROWSE: u16 = 609;
const IDC_VFILE: u16 = 610;
const IDC_VVERIFY: u16 = 611;
const IDC_VRESULT: u16 = 612;
const IDC_DFILELBL: u16 = 613;
const IDC_DFORMATLBL: u16 = 614;
const IDC_DSLOTLBL: u16 = 615;
const IDC_DPINLBL: u16 = 616;
const IDC_DREASONLBL: u16 = 617;
const IDC_VFILELBL: u16 = 618;
const IDC_VHEAD: u16 = 619;
const IDC_RGEN: u16 = 701;
const IDC_RSTOP: u16 = 702;
const IDC_RCODE: u16 = 703;
const IDC_RSTATUS: u16 = 704;
const IDC_RHOWTO: u16 = 705;
const IDC_RDEVICES: u16 = 706;
const IDC_RREMOVE: u16 = 707;
const IDC_RREFRESH: u16 = 708;
const IDC_RCODELBL: u16 = 709;
const IDC_RDEVICESLBL: u16 = 711;
const IDC_RHINT: u16 = 712;

struct AppState {
    main: HWND,
    tabs: HWND,
    statusbar: HWND,
    pages: [HWND; 5],
    readers: HWND,
    detail_reader: HWND,
    detail_atr: HWND,
    identity_rows: [HWND; 9],
    identity_status: HWND,
    photo: HWND,
    photo_caption: HWND,
    photo_hbmp: HBITMAP,
    identity_can: HWND,
    card_busy: bool,
    pin_rows: [HWND; 5],
    pin_status_msg: HWND,
    pin_mode: HWND,
    pin_labels: [HWND; 5],
    pin_fields: [HWND; 5],
    pin_result: HWND,
    pin_result_ok: Option<bool>,
    doc_file: HWND,
    doc_format: HWND,
    doc_slot: HWND,
    doc_pin: HWND,
    doc_reason: HWND,
    doc_result: HWND,
    verify_file: HWND,
    verify_result: HWND,
    remote_code: HWND,
    remote_status: HWND,
    remote_devices: HWND,
    pair_cancel: Option<Arc<AtomicBool>>,
    tints: Vec<(HWND, u32)>,
    bg_brush: HBRUSH,
    gdiplus: usize,
    // Owned for process lifetime; controls keep using the GDI objects.
    font: HFONT,
    font_title: HFONT,
    font_mono: HFONT,
    last_readers: Vec<String>,
    last_detail_for: Option<String>,
    last_atr_poll_ms: u128,
}

// Main-thread-only state. Window procedures always run on the thread
// that created the window, so thread-local storage is sufficient and
// no handle ever crosses threads. Every access snapshots owned data
// out and drops the borrow before any `SendMessageW` or card I/O, so
// re-entrant notifications can never observe a held borrow.
thread_local! {
    static STATE: RefCell<Option<AppState>> = const { RefCell::new(None) };
}

// One-shot worker results posted by card threads and picked up by
// the refresh timer. Views are owned `String`s, hence `Send`, and
// carry display text only, never secrets; neither side ever holds
// this lock together with the `STATE` borrow. At most one worker
// runs at a time (guarded by `card_busy` on the main thread), so
// the slot never collides.
enum InboxItem {
    Identity(Result<identity::IdentityView, String>),
    IdentityPhoto(
        Result<
            (
                identity::IdentityView,
                Result<identity::PhotoOutcome, String>,
            ),
            String,
        >,
    ),
    PinStatus(Result<pin::PinStatusView, String>),
    PinOp(String, bool),
    DocSign(String),
    DocVerify(String),
    PairStatus(String),
    PairDone(String, bool),
}
static INBOX: Mutex<Option<InboxItem>> = Mutex::new(None);

/// Build the full window tree invisibly and tear it down again.
/// Proves every control, font, and brush constructs without a
/// visible desktop (SSH sessions cannot show windows).
fn probe_ui() {
    match create_main_window() {
        Ok(window) => {
            // Exercise the photo pipeline too when a saved JPEG is
            // around (a `--smoke` with the test CAN leaves one).
            let photo = std::env::temp_dir().join("refineid-photo.jpg");
            let bitmap = photo.is_file() && load_photo_bitmap(&photo);
            let _ = unsafe { DestroyWindow(window) };
            println!("UI-PROBE-OK bitmap={bitmap}");
        }
        Err(error) => println!("UI-PROBE-FAIL\n{error}"),
    }
}

/// Register classes and create the main window (which builds the
/// whole control tree in `WM_CREATE`). Shared by `run` and the
/// headless `--ui-probe`.
fn create_main_window() -> windows::core::Result<HWND> {
    let class_size = u32::try_from(size_of::<INITCOMMONCONTROLSEX>()).unwrap_or(u32::MAX);
    let classes = INITCOMMONCONTROLSEX {
        dwSize: class_size,
        dwICC: ICC_TAB_CLASSES | ICC_BAR_CLASSES,
    };
    let _ = unsafe { InitCommonControlsEx(&raw const classes) };

    let instance = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_or(HINSTANCE(std::ptr::null_mut()), |module| {
            HINSTANCE(module.0)
        });
    register_class(instance, w!("RefineIDWinGui"), Some(wndproc))?;
    register_class(instance, w!("RefineIDWinGuiPage"), Some(page_proc))?;

    let title = HSTRING::from(version::build_label());
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("RefineIDWinGui"),
            &title,
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            860,
            620,
            None,
            None,
            Some(instance),
            None,
        )
    }
}

pub fn run() {
    if std::env::args().any(|arg| arg == "--smoke") {
        smoke();
        return;
    }
    if std::env::args().any(|arg| arg == "--selftest") {
        smoke_selftest();
        return;
    }
    if std::env::args().any(|arg| arg == "--ui-probe") {
        probe_ui();
        return;
    }
    if create_main_window().is_err() {
        warn("Could not create the main window.");
        return;
    }
    let mut message = MSG {
        hwnd: HWND(std::ptr::null_mut()),
        message: 0,
        wParam: WPARAM(0),
        lParam: LPARAM(0),
        time: 0,
        pt: POINT { x: 0, y: 0 },
    };
    while unsafe { GetMessageW(&raw mut message, None, 0, 0) }.as_bool() {
        let _ = unsafe { TranslateMessage(&raw const message) };
        unsafe { DispatchMessageW(&raw const message) };
    }
}

/// Headless self-check for SSH sessions, where the GUI would land
/// in invisible session 0: read the card panel and print it.
/// Read-only; no credential-bearing command is sent.
fn smoke() {
    let reader = identity::first_present_reader();
    let Some(reader) = reader else {
        println!("SMOKE-NO-CARD");
        return;
    };
    let can = std::env::var("REFINEID_TEST_CAN")
        .ok()
        .and_then(|value| identity::parse_can(value.into_bytes()).ok());
    let outcome = can.map_or_else(
        || identity::read_identity(&reader),
        |can| identity::read_identity_and_photo(&reader, can),
    );
    match outcome {
        Ok(panel) => println!("SMOKE-OK reader={reader}\n{panel}"),
        Err(error) => println!("SMOKE-READ-FAIL reader={reader}\n{error}"),
    }
}

/// Headless validation self-check: exercise `pin::prepare` with
/// synthetic buffers (good and bad) and report PASS/FAIL per case.
/// `prepare` never touches the card, so this burns no retries.
fn smoke_selftest() {
    let cases: &[(usize, &[&[u8]], bool)] = &[
        (0, &[b"1234", b"5678", b"5678"], true),
        (0, &[b"1234", b"5678", b"8765"], false),
        (0, &[b"12", b"5678", b"5678"], false),
        (0, &[b"12ab", b"5678", b"5678"], false),
        (1, &[b"123456", b"654321", b"654321"], true),
        (1, &[b"1234", b"654321", b"654321"], false),
        (2, &[b"1234567", b"1111", b"1111"], true),
        (2, &[b"1234", b"1111", b"1111"], false),
        (3, &[b"12345678", b"222222", b"222222"], true),
        (
            4,
            &[b"1234567", b"1111", b"1111", b"222222", b"222222"],
            true,
        ),
        (
            4,
            &[b"1234567", b"1111", b"1111", b"222222", b"333333"],
            false,
        ),
        (
            4,
            &[b"12345", b"1111", b"1111", b"222222", b"222222"],
            false,
        ),
        (9, &[b"1234"], false),
    ];
    let mut failures = 0;
    for (index, (mode, fields, want_ok)) in cases.iter().enumerate() {
        let buffers: Vec<Vec<u8>> = fields.iter().map(|field| field.to_vec()).collect();
        let got_ok = pin::prepare(*mode, buffers).is_ok();
        let pass = got_ok == *want_ok;
        if !pass {
            failures += 1;
        }
        println!(
            "SELFTEST case{index} mode={mode} want_ok={want_ok} got_ok={got_ok} {}",
            if pass { "PASS" } else { "FAIL" }
        );
    }
    let verdict = if failures == 0 {
        "SELFTEST-ALL-PASS"
    } else {
        "SELFTEST-FAILURES"
    };
    println!("{verdict}");
}

type WindowProc = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

fn register_class(
    instance: HINSTANCE,
    name: PCWSTR,
    proc: Option<WindowProc>,
) -> windows::core::Result<()> {
    let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }?;
    let class = WNDCLASSW {
        style: WNDCLASS_STYLES(0),
        lpfnWndProc: proc,
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: HICON(std::ptr::null_mut()),
        hCursor: cursor,
        hbrBackground: unsafe { GetSysColorBrush(COLOR_BTNFACE) },
        lpszMenuName: PCWSTR::null(),
        lpszClassName: name,
    };
    if unsafe { RegisterClassW(&raw const class) } == 0 {
        return Err(windows::core::Error::from_thread());
    }
    Ok(())
}

unsafe extern "system" fn wndproc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_CREATE => {
            if on_create(hwnd).is_err() {
                warn("Could not build the main window.");
            }
            LRESULT(0)
        }
        WM_SIZE => {
            layout();
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = low_word(wparam.0);
            let code = command_code(wparam.0);
            if lparam.0 != 0 && code == BN_CLICKED && id == IDC_REFRESH {
                refresh_readers(true);
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_IREAD {
                start_identity_read();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_IPHOTO {
                start_photo_read();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_PREFRESH {
                start_pin_status();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_PEXEC {
                start_pin_execute();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_DBROWSE {
                browse_for_file(IDC_DFILE);
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_DSIGN {
                start_doc_sign();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_VBROWSE {
                browse_for_file(IDC_VFILE);
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_VVERIFY {
                start_doc_verify();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_RGEN {
                start_pairing();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_RSTOP {
                stop_pairing();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_RREMOVE {
                remove_remote_device();
            } else if lparam.0 != 0 && code == BN_CLICKED && id == IDC_RREFRESH {
                refresh_remote_devices();
            } else if lparam.0 != 0 && code == CBN_SELCHANGE && id == IDC_PMODE {
                pin_mode_changed();
            } else if lparam.0 != 0 && code == LBN_SELCHANGE && id == IDC_READERS {
                refresh_readers(false);
            }
            LRESULT(0)
        }
        WM_NOTIFY => {
            if lparam.0 != 0 {
                let header = unsafe { &*(lparam.0 as *const NMHDR) };
                if header.code == TCN_SELCHANGE {
                    let index = current_tab();
                    select_page(index);
                    if index == 2 {
                        start_pin_status();
                    }
                }
            }
            LRESULT(0)
        }
        WM_TIMER => {
            refresh_readers(false);
            poll_inbox();
            LRESULT(0)
        }
        WM_DESTROY => {
            destroy_graphics();
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

/// Page windows paint the brand background, tint their controls,
/// and forward control notifications to the main window, which owns
/// all behavior. Holds no borrow across GDI calls or forwarding.
unsafe extern "system" fn page_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_COMMAND | WM_NOTIFY => {
            let main = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.main));
            main.map_or_else(
                || unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
                |target| unsafe { SendMessageW(target, message, Some(wparam), Some(lparam)) },
            )
        }
        WM_ERASEBKGND => {
            let brush = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.bg_brush));
            let Some(brush) = brush else {
                return unsafe { DefWindowProcW(hwnd, message, wparam, lparam) };
            };
            let hdc = HDC(wparam.0 as *mut core::ffi::c_void);
            let mut area = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            if unsafe { GetClientRect(hwnd, &raw mut area) }.is_err() {
                return LRESULT(1);
            }
            let _ = unsafe { FillRect(hdc, &raw const area, brush) };
            LRESULT(1)
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT => {
            let ctl = HWND(lparam.0 as *mut core::ffi::c_void);
            let (fg, white) = ctl_colors(message, ctl);
            let hdc = HDC(wparam.0 as *mut core::ffi::c_void);
            unsafe {
                SetTextColor(hdc, COLORREF(fg));
                SetBkColor(hdc, COLORREF(if white { WHITE } else { BG_PAGE }));
            }
            let brush = if white {
                unsafe { GetSysColorBrush(COLOR_WINDOW) }
            } else {
                STATE
                    .with(|cell| cell.borrow().as_ref().map(|state| state.bg_brush))
                    .unwrap_or(HBRUSH(std::ptr::null_mut()))
            };
            LRESULT(brush.0 as isize)
        }
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "window-construction script: the five page sections build one control tree top-to-bottom; splitting would shuttle two dozen handles and fonts across boundaries"
)]
fn on_create(main: HWND) -> windows::core::Result<()> {
    let instance = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_or(HINSTANCE(std::ptr::null_mut()), |module| {
            HINSTANCE(module.0)
        });
    let font = message_font();
    let font_title = ui_font(-20, 600, "Segoe UI");
    let font_mono = ui_font(-12, 400, "Consolas");
    let bg_brush = unsafe { CreateSolidBrush(COLORREF(BG_PAGE)) };
    let mut gdiplus = 0usize;
    let mut startup: GdiplusStartupInput = unsafe { std::mem::zeroed() };
    startup.GdiplusVersion = 1;
    let _ = unsafe { GdiplusStartup(&raw mut gdiplus, &raw const startup, std::ptr::null_mut()) };
    let mut tints: Vec<(HWND, u32)> = Vec::new();

    let tabs = child(
        w!("SysTabControl32"),
        "",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0,
        0,
        0,
        0,
        main,
        IDC_TAB,
        instance,
    )?;
    set_font(tabs, font);
    for (index, title) in TABS.iter().enumerate() {
        add_tab(tabs, index, title);
    }

    let statusbar = child(
        w!("msctls_statusbar32"),
        "",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(SBS_SIZEGRIP as u32),
        0,
        0,
        0,
        0,
        main,
        IDC_STATUSBAR,
        instance,
    )?;
    set_font(statusbar, font);

    let mut pages = [HWND(std::ptr::null_mut()); 5];
    for (index, page) in pages.iter_mut().enumerate() {
        *page = child(
            w!("RefineIDWinGuiPage"),
            "",
            WS_CHILD,
            0,
            0,
            0,
            0,
            main,
            200 + id_offset(index),
            instance,
        )?;
    }

    add_header(
        pages[0],
        instance,
        0,
        "Card status",
        "Readers and card presence",
        font_title,
        font,
        &mut tints,
    )?;
    let readers = child(
        w!("LISTBOX"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WINDOW_STYLE(LBS_NOTIFY as u32),
        16,
        68,
        320,
        170,
        pages[0],
        IDC_READERS,
        instance,
    )?;
    set_font(readers, font);
    let refresh = child(
        w!("BUTTON"),
        "Refresh",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        348,
        68,
        110,
        30,
        pages[0],
        IDC_REFRESH,
        instance,
    )?;
    set_font(refresh, font);
    let detail_reader = add_row(
        pages[0],
        instance,
        IDC_DROWLAB,
        IDC_DROW,
        250,
        "Reader",
        580,
        font,
        &mut tints,
    )?;
    let detail_atr = add_row(
        pages[0],
        instance,
        IDC_DROWLAB + 1,
        IDC_DROW + 1,
        276,
        "ATR",
        580,
        font,
        &mut tints,
    )?;
    set_font(detail_atr, font_mono);
    let stamp = child(
        w!("STATIC"),
        &version::build_label(),
        WS_CHILD | WS_VISIBLE,
        16,
        310,
        640,
        20,
        pages[0],
        IDC_SVERSION,
        instance,
    )?;
    set_font(stamp, font);
    tints.push((stamp, GRAY));

    add_header(
        pages[1],
        instance,
        1,
        "Identity",
        "Card holder and document",
        font_title,
        font,
        &mut tints,
    )?;
    let identity_read = child(
        w!("BUTTON"),
        "Read identity",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        16,
        68,
        140,
        30,
        pages[1],
        IDC_IREAD,
        instance,
    )?;
    set_font(identity_read, font);
    let can_label = child(
        w!("STATIC"),
        "CAN:",
        WS_CHILD | WS_VISIBLE,
        164,
        74,
        36,
        20,
        pages[1],
        IDC_ICANLABEL,
        instance,
    )?;
    set_font(can_label, font);
    tints.push((can_label, GRAY));
    let identity_can = child(
        w!("EDIT"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WINDOW_STYLE(ES_PASSWORD as u32),
        204,
        68,
        90,
        26,
        pages[1],
        IDC_ICAN,
        instance,
    )?;
    set_font(identity_can, font);
    // Test hook: prefill the CAN from the environment when it
    // parses. The value is never logged.
    if let Ok(prefill) = std::env::var("REFINEID_TEST_CAN")
        && refineid_lib_core::can::Can::new(&prefill).is_ok()
    {
        set_text(identity_can, &prefill);
    }
    let identity_photo = child(
        w!("BUTTON"),
        "Read photo",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        304,
        68,
        110,
        30,
        pages[1],
        IDC_IPHOTO,
        instance,
    )?;
    set_font(identity_photo, font);
    let identity_status = child(
        w!("STATIC"),
        "",
        WS_CHILD | WS_VISIBLE,
        16,
        102,
        560,
        20,
        pages[1],
        IDC_ISTATUS,
        instance,
    )?;
    set_font(identity_status, font);
    let mut identity_rows = [HWND(std::ptr::null_mut()); 9];
    for (index, label) in IDENTITY_ROW_LABELS.iter().enumerate() {
        identity_rows[index] = add_row(
            pages[1],
            instance,
            IDC_ILABEL + id_offset(index),
            IDC_IROW + id_offset(index),
            128 + layout_index(index) * 26,
            label,
            400,
            font,
            &mut tints,
        )?;
    }
    let photo = child(
        w!("STATIC"),
        "",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(SS_BITMAP.0),
        600,
        128,
        150,
        190,
        pages[1],
        IDC_PHOTO,
        instance,
    )?;
    let photo_caption = child(
        w!("STATIC"),
        "No photo",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(SS_CENTER.0),
        600,
        322,
        150,
        20,
        pages[1],
        IDC_PHOTOCAP,
        instance,
    )?;
    set_font(photo_caption, font);
    tints.push((photo_caption, GRAY));

    add_header(
        pages[2],
        instance,
        2,
        "PIN management",
        "Status, change, unblock, and activation",
        font_title,
        font,
        &mut tints,
    )?;
    let mut pin_rows = [HWND(std::ptr::null_mut()); 5];
    for (index, label) in PIN_ROW_LABELS.iter().enumerate() {
        pin_rows[index] = add_row(
            pages[2],
            instance,
            IDC_PROWLAB + id_offset(index),
            IDC_PROW + id_offset(index),
            68 + layout_index(index) * 24,
            label,
            400,
            font,
            &mut tints,
        )?;
    }
    let pin_status_msg = child(
        w!("STATIC"),
        "",
        WS_CHILD | WS_VISIBLE,
        16,
        190,
        560,
        20,
        pages[2],
        IDC_PSTATUSMSG,
        instance,
    )?;
    set_font(pin_status_msg, font);
    let pin_mode = child(
        w!("COMBOBOX"),
        "",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        16,
        214,
        280,
        140,
        pages[2],
        IDC_PMODE,
        instance,
    )?;
    set_font(pin_mode, font);
    for mode in pin::MODES {
        combo_add(pin_mode, mode);
    }
    send(pin_mode, CB_SETCURSEL, 0, 0);
    let pin_refresh = child(
        w!("BUTTON"),
        "Refresh status",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        304,
        214,
        130,
        30,
        pages[2],
        IDC_PREFRESH,
        instance,
    )?;
    set_font(pin_refresh, font);
    let mut pin_labels = [HWND(std::ptr::null_mut()); 5];
    let mut pin_fields = [HWND(std::ptr::null_mut()); 5];
    for index in 0..5 {
        let y = 252 + layout_index(index) * 30;
        pin_labels[index] = child(
            w!("STATIC"),
            "",
            WS_CHILD | WS_VISIBLE,
            16,
            y + 4,
            150,
            20,
            pages[2],
            IDC_PLAB1 + id_offset(index),
            instance,
        )?;
        set_font(pin_labels[index], font);
        tints.push((pin_labels[index], GRAY));
        pin_fields[index] = child(
            w!("EDIT"),
            "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WINDOW_STYLE(ES_PASSWORD as u32),
            174,
            y,
            180,
            24,
            pages[2],
            IDC_PF1 + id_offset(index),
            instance,
        )?;
        set_font(pin_fields[index], font);
    }
    let pin_exec = child(
        w!("BUTTON"),
        "Execute",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        370,
        252,
        120,
        30,
        pages[2],
        IDC_PEXEC,
        instance,
    )?;
    set_font(pin_exec, font);
    let pin_result = child(
        w!("EDIT"),
        "",
        WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32)
            | WINDOW_STYLE(ES_READONLY as u32)
            | WINDOW_STYLE(ES_AUTOVSCROLL as u32),
        16,
        406,
        560,
        64,
        pages[2],
        IDC_PRESULT,
        instance,
    )?;
    set_font(pin_result, font);
    pin_apply_mode(&pin_labels, &pin_fields, 0);

    add_header(
        pages[3],
        instance,
        3,
        "Document signing",
        "Sign and verify ASiC-E and PDF documents",
        font_title,
        font,
        &mut tints,
    )?;
    doc_label(
        pages[3],
        instance,
        "File",
        16,
        68,
        50,
        IDC_DFILELBL,
        font,
        &mut tints,
    )?;
    let doc_file = child(
        w!("EDIT"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        70,
        66,
        360,
        24,
        pages[3],
        IDC_DFILE,
        instance,
    )?;
    set_font(doc_file, font);
    let doc_browse = child(
        w!("BUTTON"),
        "Browse",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        440,
        66,
        90,
        24,
        pages[3],
        IDC_DBROWSE,
        instance,
    )?;
    set_font(doc_browse, font);
    doc_label(
        pages[3],
        instance,
        "Format",
        16,
        100,
        50,
        IDC_DFORMATLBL,
        font,
        &mut tints,
    )?;
    let doc_format = child(
        w!("COMBOBOX"),
        "",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        70,
        98,
        170,
        120,
        pages[3],
        IDC_DFORMAT,
        instance,
    )?;
    set_font(doc_format, font);
    combo_add(doc_format, "PDF document (.pdf)");
    combo_add(doc_format, "ASiC-E container (.asice)");
    send(doc_format, CB_SETCURSEL, 0, 0);
    doc_label(
        pages[3],
        instance,
        "Signature",
        250,
        100,
        60,
        IDC_DSLOTLBL,
        font,
        &mut tints,
    )?;
    let doc_slot = child(
        w!("COMBOBOX"),
        "",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        315,
        98,
        185,
        120,
        pages[3],
        IDC_DSLOT,
        instance,
    )?;
    set_font(doc_slot, font);
    combo_add(doc_slot, "Qualified (PIN2)");
    combo_add(doc_slot, "Authentication (PIN1)");
    send(doc_slot, CB_SETCURSEL, 0, 0);
    doc_label(
        pages[3],
        instance,
        "PIN",
        16,
        132,
        50,
        IDC_DPINLBL,
        font,
        &mut tints,
    )?;
    let doc_pin = child(
        w!("EDIT"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WINDOW_STYLE(ES_PASSWORD as u32),
        70,
        130,
        170,
        24,
        pages[3],
        IDC_DPIN,
        instance,
    )?;
    set_font(doc_pin, font);
    doc_label(
        pages[3],
        instance,
        "Reason",
        250,
        132,
        55,
        IDC_DREASONLBL,
        font,
        &mut tints,
    )?;
    let doc_reason = child(
        w!("EDIT"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        315,
        130,
        185,
        24,
        pages[3],
        IDC_DREASON,
        instance,
    )?;
    set_font(doc_reason, font);
    let doc_sign = child(
        w!("BUTTON"),
        "Sign document",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        70,
        162,
        150,
        30,
        pages[3],
        IDC_DSIGN,
        instance,
    )?;
    set_font(doc_sign, font);
    let doc_result = child(
        w!("EDIT"),
        "",
        WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32)
            | WINDOW_STYLE(ES_READONLY as u32)
            | WINDOW_STYLE(ES_AUTOVSCROLL as u32),
        16,
        200,
        544,
        96,
        pages[3],
        IDC_DRESULT,
        instance,
    )?;
    set_font(doc_result, font_mono);
    doc_label(
        pages[3],
        instance,
        "Verify a signed container",
        16,
        306,
        300,
        IDC_VHEAD,
        font_title,
        &mut tints,
    )?;
    doc_label(
        pages[3],
        instance,
        "File",
        16,
        332,
        50,
        IDC_VFILELBL,
        font,
        &mut tints,
    )?;
    let verify_file = child(
        w!("EDIT"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        70,
        330,
        360,
        24,
        pages[3],
        IDC_VFILE,
        instance,
    )?;
    set_font(verify_file, font);
    let verify_browse = child(
        w!("BUTTON"),
        "Browse",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        440,
        330,
        90,
        24,
        pages[3],
        IDC_VBROWSE,
        instance,
    )?;
    set_font(verify_browse, font);
    let verify_button = child(
        w!("BUTTON"),
        "Verify",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        70,
        360,
        120,
        28,
        pages[3],
        IDC_VVERIFY,
        instance,
    )?;
    set_font(verify_button, font);
    let verify_result = child(
        w!("EDIT"),
        "",
        WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32)
            | WINDOW_STYLE(ES_READONLY as u32)
            | WINDOW_STYLE(ES_AUTOVSCROLL as u32),
        200,
        360,
        360,
        100,
        pages[3],
        IDC_VRESULT,
        instance,
    )?;
    set_font(verify_result, font_mono);

    add_header(
        pages[4],
        instance,
        4,
        "Remote setup",
        "Pair this device with remote signing",
        font_title,
        font,
        &mut tints,
    )?;
    doc_label(
        pages[4],
        instance,
        "Pairing code",
        16,
        68,
        90,
        IDC_RCODELBL,
        font,
        &mut tints,
    )?;
    let remote_code = child(
        w!("EDIT"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        110,
        62,
        180,
        30,
        pages[4],
        IDC_RCODE,
        instance,
    )?;
    set_font(remote_code, font_title);
    tints.push((remote_code, INK));
    let pair_gen = child(
        w!("BUTTON"),
        "Pair",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        300,
        62,
        140,
        28,
        pages[4],
        IDC_RGEN,
        instance,
    )?;
    set_font(pair_gen, font);
    let pair_stop = child(
        w!("BUTTON"),
        "Stop",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        450,
        62,
        90,
        28,
        pages[4],
        IDC_RSTOP,
        instance,
    )?;
    set_font(pair_stop, font);
    let remote_status = child(
        w!("STATIC"),
        "No pairing in progress.",
        WS_CHILD | WS_VISIBLE,
        16,
        100,
        544,
        20,
        pages[4],
        IDC_RSTATUS,
        instance,
    )?;
    set_font(remote_status, font);
    tints.push((remote_status, GRAY));
    let pair_howto = child(
        w!("STATIC"),
        "On the phone:\r\n1. Open the RefineID app and go to Remote.\r\n2. Choose Enter code and type the 6-digit code above.\r\n3. Confirm the pairing on this computer when asked.",
        WS_CHILD | WS_VISIBLE,
        16,
        126,
        544,
        84,
        pages[4],
        IDC_RHOWTO,
        instance,
    )?;
    set_font(pair_howto, font);
    tints.push((pair_howto, GRAY));
    doc_label(
        pages[4],
        instance,
        "This computer and the phone must be on the same Wi-Fi network.",
        16,
        214,
        544,
        IDC_RHINT,
        font,
        &mut tints,
    )?;
    doc_label(
        pages[4],
        instance,
        "Paired devices",
        16,
        240,
        200,
        IDC_RDEVICESLBL,
        font,
        &mut tints,
    )?;
    let remote_devices = child(
        w!("LISTBOX"),
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WINDOW_STYLE(LBS_NOTIFY as u32),
        16,
        260,
        544,
        110,
        pages[4],
        IDC_RDEVICES,
        instance,
    )?;
    set_font(remote_devices, font);
    let pair_remove = child(
        w!("BUTTON"),
        "Remove",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        16,
        388,
        100,
        28,
        pages[4],
        IDC_RREMOVE,
        instance,
    )?;
    set_font(pair_remove, font);
    let pair_refresh = child(
        w!("BUTTON"),
        "Refresh",
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        126,
        388,
        100,
        28,
        pages[4],
        IDC_RREFRESH,
        instance,
    )?;
    set_font(pair_refresh, font);

    STATE.with(|cell| {
        *cell.borrow_mut() = Some(AppState {
            main,
            tabs,
            statusbar,
            pages,
            readers,
            detail_reader,
            detail_atr,
            identity_rows,
            identity_status,
            photo,
            photo_caption,
            photo_hbmp: HBITMAP(std::ptr::null_mut()),
            identity_can,
            card_busy: false,
            pin_rows,
            pin_status_msg,
            pin_mode,
            pin_labels,
            pin_fields,
            pin_result,
            pin_result_ok: None,
            doc_file,
            doc_format,
            doc_slot,
            doc_pin,
            doc_reason,
            doc_result,
            verify_file,
            verify_result,
            remote_code,
            remote_status,
            remote_devices,
            pair_cancel: None,
            tints,
            bg_brush,
            gdiplus,
            font,
            font_title,
            font_mono,
            last_readers: Vec::new(),
            last_detail_for: None,
            last_atr_poll_ms: 0,
        });
    });
    unsafe { SetTimer(Some(main), TIMER_REFRESH, REFRESH_MS, None) };
    select_page(0);
    layout();
    refresh_readers(true);
    refresh_remote_devices();
    Ok(())
}

fn layout() {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.main, state.tabs, state.statusbar, state.pages))
    });
    let Some((main, tabs, statusbar, pages)) = snapshot else {
        return;
    };
    let mut outer = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    if unsafe { GetClientRect(main, &raw mut outer) }.is_err() {
        return;
    }
    let width = outer.right - outer.left;
    let height = outer.bottom - outer.top;
    let _ = unsafe { MoveWindow(tabs, 8, 8, width - 16, height - 16 - STATUSBAR_HEIGHT, true) };
    let _ = unsafe {
        MoveWindow(
            statusbar,
            0,
            height - STATUSBAR_HEIGHT,
            width,
            STATUSBAR_HEIGHT,
            true,
        )
    };
    let mut area = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    if unsafe { GetClientRect(tabs, &raw mut area) }.is_err() {
        return;
    }
    send(tabs, TCM_ADJUSTRECT, 0, &raw mut area as isize);
    for page in pages {
        let _ = unsafe {
            MoveWindow(
                page,
                8 + area.left,
                8 + area.top,
                area.right - area.left,
                area.bottom - area.top,
                true,
            )
        };
    }
}

fn current_tab() -> usize {
    let tab = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.tabs));
    let Some(tab) = tab else {
        return 0;
    };
    let selected = send(tab, TCM_GETCURSEL, 0, 0);
    if selected < 0 || usize::try_from(selected).unwrap_or(0) >= TABS.len() {
        return 0;
    }
    usize::try_from(selected).unwrap_or(0)
}

fn select_page(index: usize) {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.tabs, state.pages))
    });
    let Some((tabs, pages)) = snapshot else {
        return;
    };
    if index >= pages.len() {
        return;
    }
    send(tabs, TCM_SETCURSEL, index, 0);
    for (page_index, page) in pages.iter().enumerate() {
        let _ = unsafe {
            ShowWindow(
                *page,
                if page_index == index {
                    SW_SHOW
                } else {
                    SW_HIDE
                },
            )
        };
    }
}

/// Re-list readers (cheap, no card contact) and refresh the ATR
/// snapshot only when the selection changed, the reader set changed,
/// the caller forced it, or the poll interval elapsed.
fn refresh_readers(force: bool) {
    let snapshot = STATE.with(|cell| {
        cell.borrow().as_ref().map(|state| {
            (
                state.readers,
                state.detail_reader,
                state.detail_atr,
                state.statusbar,
                state.last_readers.clone(),
                state.last_detail_for.clone(),
                state.last_atr_poll_ms,
                state.card_busy,
            )
        })
    });
    let Some((list, detail_reader, detail_atr, statusbar, prior, last_detail_for, last_poll, busy)) =
        snapshot
    else {
        return;
    };
    let readers = card::list_readers().unwrap_or_default();
    if force || readers != prior {
        send(list, LB_RESETCONTENT, 0, 0);
        for name in &readers {
            list_add(list, name);
        }
        STATE.with(|cell| {
            if let Some(state) = cell.borrow_mut().as_mut() {
                state.last_readers.clone_from(&readers);
            }
        });
    }
    let selected = list_selection(list).or_else(|| readers.first().cloned());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    let stale = now.saturating_sub(last_poll) >= ATR_POLL_MS;
    // Card operations hold the card exclusively; a shared ATR poll
    // alongside one would collide, so ATR snapshots pause while busy.
    if !busy && (force || stale || selected != last_detail_for) {
        if let Some(name) = selected.clone() {
            match card::reader_atr_hex(&name) {
                Ok(atr) => {
                    set_tint(detail_reader, PRIMARY);
                    set_text(detail_reader, &name);
                    set_tint(detail_atr, INK);
                    set_text(detail_atr, &atr);
                }
                Err(error) => {
                    set_tint(detail_reader, PRIMARY);
                    set_text(detail_reader, &name);
                    set_tint(detail_atr, ERROR);
                    set_text(detail_atr, &error);
                }
            }
        } else {
            set_tint(detail_reader, GRAY);
            set_text(detail_reader, "No readers found.");
            set_tint(detail_atr, GRAY);
            set_text(detail_atr, "—");
        }
        STATE.with(|cell| {
            if let Some(state) = cell.borrow_mut().as_mut() {
                state.last_detail_for = selected;
                state.last_atr_poll_ms = now;
            }
        });
    }
    if readers.is_empty() {
        set_text(statusbar, "No smart-card readers.");
    } else {
        set_text(statusbar, &format!("{} reader(s).", readers.len()));
    }
}

/// Start an identity read on a worker thread; the refresh timer
/// picks the result up from `INBOX`. Runs on the main thread only.
fn start_identity_read() {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.card_busy, state.last_detail_for.clone()))
    });
    let Some((busy, selected)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let reader = selected.or_else(identity::first_present_reader);
    let Some(reader) = reader else {
        set_identity_status("No card present.", ERROR);
        return;
    };
    set_identity_status("Reading card identity...", GRAY);
    set_card_busy(true);
    std::thread::spawn(move || {
        let outcome = identity::read_identity_view(&reader);
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::Identity(outcome));
        }
    });
}

/// Read identity plus the eMRTD photo on a worker thread; the
/// refresh timer picks the panel up from `INBOX`. The CAN is
/// parsed and wiped on the main thread; only the typed `Can`
/// crosses to the worker. Runs on the main thread only.
fn start_photo_read() {
    let snapshot = STATE.with(|cell| {
        cell.borrow().as_ref().map(|state| {
            (
                state.identity_can,
                state.card_busy,
                state.last_detail_for.clone(),
            )
        })
    });
    let Some((can_edit, busy, selected)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let reader = selected.or_else(identity::first_present_reader);
    let Some(reader) = reader else {
        set_identity_status("No card present.", ERROR);
        return;
    };
    let can = match identity::parse_can(edit_secret(can_edit)) {
        Ok(can) => can,
        Err(error) => {
            set_identity_status(&error, ERROR);
            return;
        }
    };
    set_identity_status("Reading identity and photo...", GRAY);
    set_card_busy(true);
    std::thread::spawn(move || {
        let outcome = match identity::read_identity_view(&reader) {
            Ok(view) => {
                let photo = identity::read_photo_saved(&reader, can);
                Ok((view, photo))
            }
            Err(error) => Err(error),
        };
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::IdentityPhoto(outcome));
        }
    });
}

fn poll_inbox() {
    let item = INBOX.lock().ok().and_then(|mut inbox| inbox.take());
    let Some(item) = item else {
        return;
    };
    match item {
        InboxItem::Identity(outcome) => {
            match outcome {
                Ok(view) => {
                    fill_identity_rows(&view);
                    set_identity_status("", INK);
                }
                Err(error) => set_identity_status(&error, ERROR),
            }
            set_card_busy(false);
        }
        InboxItem::IdentityPhoto(outcome) => {
            match outcome {
                Ok((view, photo)) => {
                    fill_identity_rows(&view);
                    match photo {
                        Ok(outcome) => show_photo_result(&outcome),
                        Err(error) => {
                            set_identity_status(&error, ERROR);
                        }
                    }
                }
                Err(error) => set_identity_status(&error, ERROR),
            }
            set_card_busy(false);
        }
        InboxItem::PinStatus(outcome) => {
            match outcome {
                Ok(view) => {
                    fill_pin_rows(&view);
                    set_pin_status_msg("", INK);
                }
                Err(error) => set_pin_status_msg(&error, ERROR),
            }
            set_card_busy(false);
        }
        InboxItem::PinOp(text, ok) => {
            set_pin_result(&text, Some(ok));
            set_card_busy(false);
            // Card-side counters changed; re-read the status pane.
            start_pin_status();
        }
        InboxItem::DocSign(text) => {
            set_doc_result(&text);
            set_card_busy(false);
        }
        InboxItem::DocVerify(text) => {
            set_verify_result(&text);
            set_card_busy(false);
        }
        InboxItem::PairStatus(status) => {
            set_remote_status(&status);
        }
        InboxItem::PairDone(text, ok) => {
            set_remote_status(&text);
            set_card_busy(false);
            STATE.with(|cell| {
                if let Some(state) = cell.borrow_mut().as_mut() {
                    state.pair_cancel = None;
                }
            });
            if ok {
                refresh_remote_devices();
                info(&text);
            }
        }
    }
}

fn fill_identity_rows(view: &identity::IdentityView) {
    let rows = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.identity_rows));
    let Some(rows) = rows else {
        return;
    };
    set_tint(rows[0], PRIMARY);
    set_text(rows[0], &view.reader);
    set_tint(rows[1], INK);
    set_text(rows[1], &view.serial);
    set_tint(rows[2], PRIMARY);
    set_text(rows[2], &view.holder);
    set_tint(rows[3], INK);
    set_text(rows[3], &view.card);
    set_tint(rows[4], INK);
    set_text(rows[4], view.generation);
    set_tint(rows[5], INK);
    set_text(rows[5], view.activation.as_deref().unwrap_or("—"));
    for (slot, state) in [(6, &view.pin1), (7, &view.pin2), (8, &view.puk)] {
        set_tint(rows[slot], state_color(state.kind));
        set_text(rows[slot], &state.text);
    }
}

fn fill_pin_rows(view: &pin::PinStatusView) {
    let rows = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.pin_rows));
    let Some(rows) = rows else {
        return;
    };
    set_tint(rows[0], PRIMARY);
    set_text(rows[0], &view.holder);
    set_tint(rows[1], INK);
    set_text(rows[1], &view.serial);
    for (slot, state) in [(2, &view.pin1), (3, &view.pin2), (4, &view.puk)] {
        set_tint(rows[slot], state_color(state.kind));
        set_text(rows[slot], &state.text);
    }
}

fn set_identity_status(text: &str, color: u32) {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.identity_status));
    if let Some(status) = target {
        set_tint(status, color);
        set_text(status, text);
    }
}

fn set_pin_status_msg(text: &str, color: u32) {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.pin_status_msg));
    if let Some(msg) = target {
        set_tint(msg, color);
        set_text(msg, text);
    }
}

fn set_pin_result(text: &str, ok: Option<bool>) {
    STATE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.pin_result_ok = ok;
        }
    });
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.pin_result));
    if let Some(result) = target {
        set_text(result, text);
    }
}

fn show_photo_result(outcome: &identity::PhotoOutcome) {
    set_identity_status(&outcome.report, GRAY);
    let caption = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.photo_caption));
    let Some(caption) = caption else {
        return;
    };
    if let Some(path) = outcome.display_jpeg.as_ref() {
        if load_photo_bitmap(path) {
            set_tint(caption, GRAY);
            set_text(caption, "Card photo");
        } else {
            set_tint(caption, ERROR);
            set_text(caption, "Photo display failed");
        }
    } else {
        set_tint(caption, GRAY);
        set_text(caption, "No displayable photo");
    }
}

/// Load a JPEG into the photo well, scaled to fit 150x190 on a
/// white ground. Any failure leaves the previous bitmap and
/// reports `false`. Main thread only.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "photo-well geometry: dimensions are small positive pixel counts, exactly representable in f32, and the float-to-int scale factors saturate rather than wrap"
)]
fn load_photo_bitmap(path: &Path) -> bool {
    const W: i32 = 150;
    const H: i32 = 190;
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.photo));
    let Some(well) = target else {
        return false;
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut bitmap: *mut GpBitmap = std::ptr::null_mut();
        if GdipCreateBitmapFromFile(PCWSTR(wide.as_ptr()), &raw mut bitmap).0 != 0
            || bitmap.is_null()
        {
            return false;
        }
        let image = bitmap.cast::<GpImage>();
        let (mut w, mut h) = (0.0f32, 0.0f32);
        if GdipGetImageDimension(image, &raw mut w, &raw mut h).0 != 0 || w <= 0.0 || h <= 0.0 {
            GdipDisposeImage(image);
            return false;
        }
        let scale = ((W as f32) / w).min((H as f32) / h);
        let dw = (w * scale) as i32;
        let dh = (h * scale) as i32;
        let dx = (W - dw) / 2;
        let dy = (H - dh) / 2;
        let hdc = GetDC(Some(well));
        if hdc.0.is_null() {
            GdipDisposeImage(image);
            return false;
        }
        let mem = CreateCompatibleDC(Some(hdc));
        let hbmp = CreateCompatibleBitmap(hdc, W, H);
        ReleaseDC(Some(well), hdc);
        if mem.0.is_null() || hbmp.0.is_null() {
            if !mem.0.is_null() {
                let _ = DeleteDC(mem);
            }
            if !hbmp.0.is_null() {
                let _ = DeleteObject(HGDIOBJ(hbmp.0));
            }
            GdipDisposeImage(image);
            return false;
        }
        let previous = SelectObject(mem, HGDIOBJ(hbmp.0));
        let mut graphics: *mut GpGraphics = std::ptr::null_mut();
        let mut ok = GdipCreateFromHDC(mem, &raw mut graphics).0 == 0 && !graphics.is_null();
        if ok {
            ok = GdipGraphicsClear(graphics, 0xFFFF_FFFF).0 == 0
                && GdipDrawImageRectI(graphics, image, dx, dy, dw, dh).0 == 0;
            GdipDeleteGraphics(graphics);
        }
        GdipDisposeImage(image);
        SelectObject(mem, previous);
        let _ = DeleteDC(mem);
        if !ok {
            let _ = DeleteObject(HGDIOBJ(hbmp.0));
            return false;
        }
        send(well, STM_SETIMAGE, IMAGE_BITMAP.0 as usize, hbmp.0 as isize);
        STATE.with(|cell| {
            if let Some(state) = cell.borrow_mut().as_mut() {
                let prev = std::mem::replace(&mut state.photo_hbmp, hbmp);
                if !prev.0.is_null() {
                    let _ = DeleteObject(HGDIOBJ(prev.0));
                }
            }
        });
        true
    }
}

fn set_card_busy(busy: bool) {
    STATE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.card_busy = busy;
        }
    });
}

/// Apply a PIN mode's field labels, hiding unused rows and wiping
/// any typed-but-unexecuted secrets from the fields.
fn pin_apply_mode(labels: &[HWND; 5], fields: &[HWND; 5], index: usize) {
    let Some(row) = pin::FIELDS.get(index) else {
        return;
    };
    for (slot, label) in row.iter().enumerate() {
        let show = !label.is_empty();
        set_text(labels[slot], label);
        set_text(fields[slot], "");
        let _ = unsafe { ShowWindow(labels[slot], if show { SW_SHOW } else { SW_HIDE }) };
        let _ = unsafe { ShowWindow(fields[slot], if show { SW_SHOW } else { SW_HIDE }) };
    }
}

fn pin_mode_changed() {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.pin_mode, state.pin_labels, state.pin_fields))
    });
    let Some((mode, labels, fields)) = snapshot else {
        return;
    };
    let index = send(mode, CB_GETCURSEL, 0, 0);
    if index < 0 {
        return;
    }
    pin_apply_mode(&labels, &fields, usize::try_from(index).unwrap_or(0));
}

/// Read a password field into a digit buffer. Non-`u8` units
/// degrade to `b'?'` (rejected downstream as non-digits); the
/// window buffer is wiped before return, and the caller moves the
/// bytes into a zeroizing `PinBytes` as the next step.
fn edit_secret(edit: HWND) -> Vec<u8> {
    let mut buffer = [0u16; 64];
    let copied = send(edit, WM_GETTEXT, buffer.len(), buffer.as_mut_ptr() as isize);
    let mut out = Vec::new();
    if copied > 0 {
        out.reserve(usize::try_from(copied).unwrap_or(0));
        for unit in buffer.iter().take(usize::try_from(copied).unwrap_or(0)) {
            out.push(u8::try_from(*unit).unwrap_or(b'?'));
        }
    }
    buffer.zeroize();
    out
}

/// Read PIN statuses on a worker thread; the refresh timer picks
/// the panel up from `INBOX`. Runs on the main thread only.
fn start_pin_status() {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.card_busy, state.last_detail_for.clone()))
    });
    let Some((busy, selected)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let reader = selected.or_else(identity::first_present_reader);
    let Some(reader) = reader else {
        set_pin_status_msg("No card present.", ERROR);
        return;
    };
    set_pin_status_msg("Reading PIN status...", GRAY);
    set_card_busy(true);
    std::thread::spawn(move || {
        let outcome = pin::read_status_view(&reader);
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::PinStatus(outcome));
        }
    });
}

/// Validate the visible fields locally, then run the PIN operation
/// on a worker thread. Runs on the main thread only.
fn start_pin_execute() {
    let snapshot = STATE.with(|cell| {
        cell.borrow().as_ref().map(|state| {
            (
                state.pin_mode,
                state.pin_fields,
                state.card_busy,
                state.last_detail_for.clone(),
            )
        })
    });
    let Some((mode, fields, busy, selected)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let index = send(mode, CB_GETCURSEL, 0, 0);
    if index < 0 || usize::try_from(index).unwrap_or(0) >= pin::MODES.len() {
        return;
    }
    let reader = selected.or_else(identity::first_present_reader);
    let Some(reader) = reader else {
        set_pin_result("No card present.", None);
        return;
    };
    let count = pin::FIELDS[usize::try_from(index).unwrap_or(0)]
        .iter()
        .filter(|label| !label.is_empty())
        .count();
    let mut buffers = Vec::with_capacity(count);
    for field in fields.iter().take(count) {
        buffers.push(edit_secret(*field));
    }
    for field in &fields {
        set_text(*field, "");
    }
    let job = match pin::prepare(usize::try_from(index).unwrap_or(0), buffers) {
        Ok(job) => job,
        Err(error) => {
            set_pin_result(&error, Some(false));
            return;
        }
    };
    set_pin_result("Working...", None);
    set_card_busy(true);
    std::thread::spawn(move || {
        let (text, ok) = match pin::run_job(job, &reader) {
            Ok(done) => (done, true),
            Err(error) => (format!("Failed:\r\n{error}"), false),
        };
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::PinOp(text, ok));
        }
    });
}

/// Grey static label on a page. Handles need no later updates.
#[allow(
    clippy::too_many_arguments,
    reason = "row builders take window handles, ids, text, and metrics as flat parameters; a builder struct would just rename the argument list"
)]
fn doc_label(
    page: HWND,
    instance: HINSTANCE,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    id: u16,
    font: HFONT,
    tints: &mut Vec<(HWND, u32)>,
) -> windows::core::Result<()> {
    let label = child(
        w!("STATIC"),
        text,
        WS_CHILD | WS_VISIBLE,
        x,
        y,
        width,
        20,
        page,
        id,
        instance,
    )?;
    set_font(label, font);
    tints.push((label, GRAY));
    Ok(())
}

/// Read an edit control's text (UTF-16, lossy). Used for file
/// paths and the signature reason; never for secrets, which go
/// through [`edit_secret`] into zeroizing buffers.
fn get_text(edit: HWND) -> String {
    let len = send(edit, WM_GETTEXTLENGTH, 0, 0);
    if len <= 0 {
        return String::new();
    }
    let capacity = usize::try_from(len).unwrap_or(0).saturating_add(1);
    let mut buffer = vec![0u16; capacity];
    let copied = send(edit, WM_GETTEXT, buffer.len(), buffer.as_mut_ptr() as isize);
    let used = usize::try_from(copied).unwrap_or(0).min(buffer.len());
    buffer.truncate(used);
    String::from_utf16_lossy(&buffer)
}

/// Common file-open dialog; writes the pick into the edit
/// control named by `target`. Returns silently on cancel. Main
/// thread only (modal dialog).
fn browse_for_file(target: u16) {
    let snapshot = STATE.with(|cell| {
        cell.borrow().as_ref().map(|state| {
            let edit = if target == IDC_DFILE {
                state.doc_file
            } else {
                state.verify_file
            };
            (state.pages[3], edit)
        })
    });
    let Some((owner, edit)) = snapshot else {
        return;
    };
    let mut filter: Vec<u16> = "All files".encode_utf16().collect();
    filter.push(0);
    filter.extend("*.*".encode_utf16());
    filter.push(0);
    filter.push(0);
    let mut file = vec![0u16; 1024];
    let mut params: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    params.lStructSize = u32::try_from(size_of::<OPENFILENAMEW>()).unwrap_or(u32::MAX);
    params.hwndOwner = owner;
    params.lpstrFilter = PCWSTR(filter.as_ptr());
    params.nFilterIndex = 1;
    params.lpstrFile = PWSTR(file.as_mut_ptr());
    params.nMaxFile = u32::try_from(file.len()).unwrap_or(0);
    params.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    let picked = unsafe { GetOpenFileNameW(&raw mut params) };
    if picked.as_bool() {
        let first = file.split(|unit| *unit == 0).next().unwrap_or(&[]);
        set_text(edit, &String::from_utf16_lossy(first));
    }
}

/// Write the sign outcome into the Document result box. Main
/// thread only; called from the inbox poll.
fn set_doc_result(text: &str) {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.doc_result));
    if let Some(result) = target {
        set_text(result, text);
    }
}

/// Write the verify outcome into the Document verify box. Main
/// thread only; called from the inbox poll.
fn set_verify_result(text: &str) {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.verify_result));
    if let Some(result) = target {
        set_text(result, text);
    }
}

/// Gather the Document page and sign on a worker thread; the
/// refresh timer picks the outcome up from `INBOX`. The PIN is
/// read into a zeroizing buffer on the main thread and moved
/// into the worker; it never touches the result text. Baseline
/// level only: no TSA, no long-term material yet.
fn start_doc_sign() {
    let snapshot = STATE.with(|cell| {
        cell.borrow().as_ref().map(|state| {
            (
                state.doc_file,
                state.doc_format,
                state.doc_slot,
                state.doc_pin,
                state.doc_reason,
                state.card_busy,
            )
        })
    });
    let Some((file_edit, format_combo, slot_combo, pin_edit, reason_edit, busy)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let path = get_text(file_edit);
    if path.trim().is_empty() {
        set_doc_result("Choose a file to sign first.");
        return;
    }
    let format = if send(format_combo, CB_GETCURSEL, 0, 0) == 1 {
        Format::AsicECades
    } else {
        Format::Pades
    };
    let slot = if send(slot_combo, CB_GETCURSEL, 0, 0) == 1 {
        SignSlot::Auth
    } else {
        SignSlot::Qualified
    };
    let input = PathBuf::from(path);
    if format == Format::Pades && !is_pdf(&input) {
        set_doc_result("PDF signing needs a .pdf file. Pick an ASiC-E container for other files.");
        return;
    }
    let pin = match PinBytes::new(edit_secret(pin_edit)) {
        Ok(pin) => pin,
        Err(error) => {
            set_doc_result(&format!("PIN rejected: {error}"));
            return;
        }
    };
    let reason = get_text(reason_edit);
    let metadata = SignatureMetadata {
        reason: if reason.trim().is_empty() {
            None
        } else {
            Some(reason)
        },
        location: None,
        contact: None,
        name: None,
        signing_time: None,
        visible_signature: None,
    };
    let output = derive_output(&input, format);
    let request = DocumentRequest {
        format,
        additional_inputs: Vec::new(),
        signing_time: SigningTime::now(),
        metadata,
        expected_serial: None,
        visible_signature: None,
        archive: false,
        long_term: false,
        timestamp_authorities: Vec::new(),
        timestamp_credentials: None,
    };
    let options = SignOptions {
        input,
        output,
        pin,
        save_cert: None,
        reader_filter: None,
        can: None,
        document: Some(request),
    };
    set_doc_result("Signing…");
    set_card_busy(true);
    std::thread::spawn(move || {
        let text = match sign_with_slot(PcscBackend, slot, options) {
            Ok(report) => render_sign_report(&report),
            Err(error) => format!("Signing failed:\r\n{error}"),
        };
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::DocSign(text));
        }
    });
}

/// Verify a signed container on a worker thread; the refresh
/// timer picks the outcome up from `INBOX`. Verify is offline:
/// no card, no PIN, no network.
fn start_doc_verify() {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.verify_file, state.card_busy))
    });
    let Some((file_edit, busy)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let path = get_text(file_edit);
    if path.trim().is_empty() {
        set_verify_result("Choose a container to verify first.");
        return;
    }
    set_verify_result("Verifying…");
    set_card_busy(true);
    std::thread::spawn(move || {
        let text = match verify_document(Path::new(&path)) {
            Ok(report) => report.render(),
            Err(error) => format!("Verify failed:\r\n{error}"),
        };
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::DocVerify(text));
        }
    });
}

/// Pair with the code the phone shows, on a worker thread; the
/// refresh timer picks progress and the outcome up from `INBOX`. The
/// phone advertises a pairing-mode record over DNS-SD and serves its
/// offer on the connection (RAPP v26.10.9 section 4.2); this side
/// browses, dials, and types the code into `CPace`.
fn start_pairing() {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.main, state.remote_code, state.card_busy))
    });
    let Some((main, code_edit, busy)) = snapshot else {
        return;
    };
    if busy {
        return;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    STATE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.pair_cancel = Some(cancel.clone());
        }
    });
    let Some(code) = normalize_pairing_code(&get_text(code_edit)) else {
        set_remote_status("Type the six characters the phone shows.");
        STATE.with(|cell| {
            if let Some(state) = cell.borrow_mut().as_mut() {
                state.pair_cancel = None;
            }
        });
        return;
    };
    set_remote_status("Starting…");
    set_card_busy(true);
    // `HWND` is a raw pointer and not `Send`; the worker only needs
    // it back for the confirm dialog, guarded by `IsWindow`.
    let main_raw = main.0 as usize;
    std::thread::spawn(move || {
        let (text, ok) = match run_pair_browse(main_raw, &code, &cancel) {
            Ok(text) => (text, true),
            Err(text) => (text, false),
        };
        if let Ok(mut inbox) = INBOX.lock() {
            *inbox = Some(InboxItem::PairDone(text, ok));
        }
    });
}

/// Ask the pairing worker to stop; the outcome still arrives
/// through `INBOX` so the busy flag clears in one place.
fn stop_pairing() {
    STATE.with(|cell| {
        if let Some(state) = cell.borrow().as_ref()
            && let Some(cancel) = state.pair_cancel.as_ref()
        {
            cancel.store(true, Ordering::SeqCst);
            set_remote_status("Stopping…");
        }
    });
}

/// Blocking browse-and-dial loop: find a phone in pairing mode and
/// pair with the typed code, until it pairs, the offer lifetime
/// passes, or `cancel` trips. Runs on the pairing worker, never on
/// the UI thread.
fn run_pair_browse(main_raw: usize, code: &str, cancel: &AtomicBool) -> Result<String, String> {
    use std::time::Instant;
    post_pair_status("Looking for the phone…");
    let mut requester = Requester::new(
        RequesterConfig {
            display_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".to_owned()),
            platform: "Windows".into(),
        },
        CredentialPairingStore::load()
            .map_err(|error| format!("Cannot open pairing store: {error}"))?,
        MemoryJournal::new(),
    );
    let deadline = Instant::now() + Duration::from_millis(OFFER_TTL_MS);
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err("Pairing stopped.".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("No phone in pairing mode was found.".to_owned());
        }
        for service in refineid_rapp_core::stream::browse(
            refineid_rapp_core::stream::DiscoveryMode::Pairing,
            Duration::from_millis(600),
        ) {
            if cancel.load(Ordering::SeqCst) {
                return Err("Pairing stopped.".to_owned());
            }
            post_pair_status("Phone found — pairing…");
            if let Ok(transport) = refineid_rapp_core::stream::dial(
                &service.endpoints,
                refineid_rapp_core::stream::STREAM_CANDIDATE_ID,
                Duration::from_secs(10),
                &StreamRendezvous::Pairing,
            ) && let Some(outcome) = attempt_pair(&mut requester, code, transport, main_raw)
            {
                return outcome;
            }
        }
    }
}

/// One pairing attempt over an established transport. `Some` is
/// terminal: success, a mistyped code, or a refusal; `None` reposts
/// a failure that leaves the next phone to be tried.
fn attempt_pair(
    requester: &mut Requester<CredentialPairingStore, MemoryJournal>,
    code: &str,
    transport: impl FrameTransport,
    main_raw: usize,
) -> Option<Result<String, String>> {
    match requester.pair_with_code(code, transport, |peer, requested| {
        confirm_pairing_dialog(main_raw, &peer.display_name, &peer.platform, requested)
    }) {
        Ok(pair_id) => Some(paired_summary(requester, pair_id)),
        Err(PairingError::CodeMismatch) => Some(Err(
            "The code does not match the one the phone shows.".to_owned(),
        )),
        Err(PairingError::DeniedLocally | PairingError::AbortedByPeer) => {
            Some(Err("The pairing was declined.".to_owned()))
        }
        Err(error) => {
            post_pair_status(&format!(
                "Pairing attempt failed ({error:?}) — still looking for the phone."
            ));
            None
        }
    }
}

/// Yes/No grants question. Runs on the pairing worker; the dialog
/// is owned by the main window so it stays on top of the app. If
/// the window is already gone (app closing mid-pair), the pairing
/// is declined rather than confirmed against a dead owner.
fn confirm_pairing_dialog(
    main_raw: usize,
    peer_name: &str,
    platform: &str,
    requested: &[String],
) -> Option<Vec<String>> {
    let owner = HWND(main_raw as *mut core::ffi::c_void);
    if !unsafe { IsWindow(Some(owner)) }.as_bool() {
        return None;
    }
    let body = HSTRING::from(format!("Pair with {peer_name} ({platform})?"));
    let caption = HSTRING::from("Confirm pairing");
    let answer = unsafe { MessageBoxW(Some(owner), &body, &caption, MB_YESNO | MB_ICONQUESTION) };
    if answer == IDYES {
        Some(requested.to_vec())
    } else {
        None
    }
}

/// Success text naming the freshly stored pairing.
fn paired_summary(
    requester: &Requester<CredentialPairingStore, MemoryJournal>,
    pair_id: PairId,
) -> Result<String, String> {
    let record = requester
        .store()
        .get(pair_id)
        .map_err(|error| format!("Stored pairing unreadable: {error:?}"))?;
    Ok(format!(
        "Paired with {} ({}).",
        record.peer_display_name, record.peer_platform
    ))
}

/// Post a pairing status line; the inbox poll applies it.
fn post_pair_status(status: &str) {
    if let Ok(mut inbox) = INBOX.lock() {
        *inbox = Some(InboxItem::PairStatus(status.to_owned()));
    }
}

/// Write the Remote status line. Main thread only.
fn set_remote_status(text: &str) {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.remote_status));
    if let Some(status) = target {
        set_text(status, text);
    }
}

/// Refill the paired-devices list from the credential vault. The
/// usable pairing carries a `*` marker, mirroring the CLI.
fn refresh_remote_devices() {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.remote_devices));
    let Some(list) = target else {
        return;
    };
    send(list, LB_RESETCONTENT, 0, 0);
    match CredentialPairingStore::load() {
        Ok(store) => {
            let current = store.usable_pairing().map(|usable| usable.pair_id);
            for (index, record) in store.records().iter().enumerate() {
                let marker = if current == Some(record.pair_id) {
                    "* "
                } else {
                    "  "
                };
                list_add(
                    list,
                    &format!(
                        "{marker}[{index}] {} ({})",
                        record.peer_display_name, record.peer_platform
                    ),
                );
            }
        }
        Err(error) => set_remote_status(&format!("Pairing store unavailable: {error}")),
    }
}

/// Remove the selected pairing from the vault, then refresh.
fn remove_remote_device() {
    let target = STATE.with(|cell| cell.borrow().as_ref().map(|state| state.remote_devices));
    let Some(list) = target else {
        return;
    };
    let selected = send(list, LB_GETCURSEL, 0, 0);
    if selected < 0 {
        set_remote_status("Select a device first.");
        return;
    }
    let Ok(index) = usize::try_from(selected) else {
        return;
    };
    let mut store = match CredentialPairingStore::load() {
        Ok(store) => store,
        Err(error) => {
            set_remote_status(&format!("Pairing store unavailable: {error}"));
            return;
        }
    };
    let Some(record) = store.records().get(index) else {
        set_remote_status("Select a device first.");
        return;
    };
    let pair_id = record.pair_id;
    match store.remove(pair_id) {
        Ok(()) => {
            refresh_remote_devices();
            set_remote_status("Pairing removed.");
        }
        Err(error) => set_remote_status(&format!("Remove failed: {error:?}")),
    }
}

/// One-line-per-fact sign summary for the result box. Paths and
/// counts only; no PIN, no serial.
fn render_sign_report(report: &SignReport) -> String {
    let signer = report
        .cert_subject_cn
        .as_ref()
        .map_or("unknown signer", CommonName::as_str);
    let slot = match report.slot {
        SignSlot::Qualified => "qualified",
        SignSlot::Auth => "authentication",
    };
    format!(
        "Signed:\r\n{}\r\n{} bytes · {slot} signature · local verify: {}\r\nSigner: {signer}",
        report.signature_path.display(),
        report.output_len,
        report.local_verify,
        signer = signer,
    )
}

/// Output next to the input: `-signed.pdf` for PDF signatures,
/// `.asice` appended for containers.
fn derive_output(input: &Path, format: Format) -> PathBuf {
    if format == Format::Pades {
        let stem = input
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("document");
        input.with_file_name(format!("{stem}-signed.pdf"))
    } else {
        let name = input
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("document");
        input.with_file_name(format!("{name}.asice"))
    }
}

/// `true` for a `.pdf` extension in any ASCII case.
fn is_pdf(input: &Path) -> bool {
    input
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
}

fn combo_add(combo: HWND, text: &str) {
    let wide = utf16_nul(text);
    send(combo, CB_ADDSTRING, 0, wide.as_ptr() as isize);
}

const IDENTITY_ROW_LABELS: [&str; 9] = [
    "Reader",
    "Serial",
    "Holder",
    "Card",
    "Generation",
    "Activation code",
    "PIN1",
    "PIN2",
    "PUK",
];
const PIN_ROW_LABELS: [&str; 5] = ["Holder", "Serial", "PIN1", "PIN2", "PUK"];

/// Add a title + subtitle header. Handles need no later updates.
#[allow(
    clippy::too_many_arguments,
    reason = "row builders take window handles, ids, text, and metrics as flat parameters; a builder struct would just rename the argument list"
)]
fn add_header(
    page: HWND,
    instance: HINSTANCE,
    index: usize,
    title: &str,
    sub: &str,
    title_font: HFONT,
    body_font: HFONT,
    tints: &mut Vec<(HWND, u32)>,
) -> windows::core::Result<()> {
    let head = child(
        w!("STATIC"),
        title,
        WS_CHILD | WS_VISIBLE,
        16,
        12,
        640,
        28,
        page,
        IDC_HEAD + id_offset(index),
        instance,
    )?;
    set_font(head, title_font);
    let subhead = child(
        w!("STATIC"),
        sub,
        WS_CHILD | WS_VISIBLE,
        16,
        40,
        640,
        20,
        page,
        IDC_SUBHEAD + id_offset(index),
        instance,
    )?;
    set_font(subhead, body_font);
    tints.push((subhead, GRAY));
    Ok(())
}

/// Add one label/value row; returns the value handle. The label is
/// gray; the value starts dark and re-tints via `set_tint`.
#[allow(
    clippy::too_many_arguments,
    reason = "row builders take window handles, ids, text, and metrics as flat parameters; a builder struct would just rename the argument list"
)]
fn add_row(
    page: HWND,
    instance: HINSTANCE,
    label_id: u16,
    value_id: u16,
    y: i32,
    label: &str,
    value_width: i32,
    body_font: HFONT,
    tints: &mut Vec<(HWND, u32)>,
) -> windows::core::Result<HWND> {
    let lab = child(
        w!("STATIC"),
        label,
        WS_CHILD | WS_VISIBLE,
        16,
        y,
        140,
        20,
        page,
        label_id,
        instance,
    )?;
    set_font(lab, body_font);
    tints.push((lab, GRAY));
    let value = child(
        w!("STATIC"),
        "—",
        WS_CHILD | WS_VISIBLE,
        164,
        y,
        value_width,
        20,
        page,
        value_id,
        instance,
    )?;
    set_font(value, body_font);
    Ok(value)
}

/// Resolve control colors: (text COLORREF, white-background).
/// Snapshots out of `STATE`; holds no borrow for the GDI calls.
fn ctl_colors(message: u32, ctl: HWND) -> (u32, bool) {
    let snapshot = STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| (state.pin_result, state.pin_result_ok, state.tints.clone()))
    });
    let Some((pin_result, pin_ok, tints)) = snapshot else {
        return (INK, message == WM_CTLCOLOREDIT);
    };
    if ctl == pin_result {
        let fg = match pin_ok {
            Some(true) => SUCCESS,
            Some(false) => ERROR,
            None => INK,
        };
        return (fg, true);
    }
    if message == WM_CTLCOLOREDIT {
        return (INK, true);
    }
    for (hwnd, color) in &tints {
        if *hwnd == ctl {
            return (*color, false);
        }
    }
    (INK, false)
}

/// Set (or replace) a STATIC's text color. Call before `set_text`;
/// the repaint picks the color up.
fn set_tint(hwnd: HWND, color: u32) {
    STATE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            if let Some(slot) = state.tints.iter_mut().find(|slot| slot.0 == hwnd) {
                slot.1 = color;
            } else {
                state.tints.push((hwnd, color));
            }
        }
    });
}

const fn state_color(kind: identity::StateKind) -> u32 {
    match kind {
        identity::StateKind::Ok => SUCCESS,
        identity::StateKind::Warn => WARNING,
        identity::StateKind::Bad => ERROR,
        identity::StateKind::Neutral => INK,
    }
}

/// Release owned GDI objects and shut GDI+ down. Main thread only.
fn destroy_graphics() {
    STATE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            let brush = std::mem::replace(&mut state.bg_brush, HBRUSH(std::ptr::null_mut()));
            let hbmp = std::mem::replace(&mut state.photo_hbmp, HBITMAP(std::ptr::null_mut()));
            let token = std::mem::replace(&mut state.gdiplus, 0);
            let font = std::mem::replace(&mut state.font, HFONT(std::ptr::null_mut()));
            let title = std::mem::replace(&mut state.font_title, HFONT(std::ptr::null_mut()));
            let mono = std::mem::replace(&mut state.font_mono, HFONT(std::ptr::null_mut()));
            unsafe {
                for object in [brush.0, hbmp.0] {
                    if !object.is_null() {
                        let _ = DeleteObject(HGDIOBJ(object));
                    }
                }
                for object in [font.0, title.0, mono.0] {
                    if !object.is_null() {
                        let _ = DeleteObject(HGDIOBJ(object));
                    }
                }
                if token != 0 {
                    GdiplusShutdown(token);
                }
            }
        }
    });
}

fn ui_font(height: i32, weight: i32, face: &str) -> HFONT {
    let wide = utf16_nul(face);
    unsafe {
        CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            FONT_OUTPUT_PRECISION(0),
            FONT_CLIP_PRECISION(0),
            DEFAULT_QUALITY,
            0,
            PCWSTR(wide.as_ptr()),
        )
    }
}

fn list_selection(list: HWND) -> Option<String> {
    let index = send(list, LB_GETCURSEL, 0, 0);
    if index < 0 {
        return None;
    }
    let length = send(list, LB_GETTEXTLEN, usize::try_from(index).unwrap_or(0), 0);
    if length <= 0 || length > 4096 {
        return None;
    }
    let mut buffer = vec![0u16; usize::try_from(length).unwrap_or(0) + 1];
    let copied = send(
        list,
        LB_GETTEXT,
        usize::try_from(index).unwrap_or(0),
        buffer.as_mut_ptr() as isize,
    );
    if copied <= 0 {
        return None;
    }
    String::from_utf16(&buffer[..usize::try_from(copied).unwrap_or(0)]).ok()
}

/// Low 16 bits of a message parameter: control id, notification
/// code (`LOWORD`). Win32 packs these by contract; the mask
/// documents the width.
#[allow(
    clippy::cast_possible_truncation,
    reason = "Win32 message cracking takes the low 16 bits by contract (LOWORD)"
)]
const fn low_word(value: usize) -> u16 {
    (value & 0xFFFF) as u16
}

/// Notification code out of a `WM_COMMAND` `WPARAM`: the id and
/// code live in the low 32 bits, compared against `u32`
/// constants (`HIWORD` widened).
#[allow(
    clippy::cast_possible_truncation,
    reason = "WM_COMMAND packs id and code in the low 32 bits of WPARAM; the high bits are zero"
)]
const fn command_code(value: usize) -> u32 {
    (value >> 16) as u32
}

/// Loop index as a control-id offset. Id-building loops run over
/// single-digit row counts, so the value always fits.
#[allow(
    clippy::cast_possible_truncation,
    reason = "control-id loops enumerate fewer than ten rows; the index always fits u16"
)]
const fn id_offset(index: usize) -> u16 {
    index as u16
}

/// Loop index as a pixel coordinate. Layout loops run over
/// single-digit row counts, so the value always fits.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "layout loops enumerate fewer than ten rows; the index always fits i32"
)]
const fn layout_index(index: usize) -> i32 {
    index as i32
}

fn send(hwnd: HWND, message: u32, wparam: usize, lparam: isize) -> isize {
    unsafe { SendMessageW(hwnd, message, Some(WPARAM(wparam)), Some(LPARAM(lparam))) }.0
}

fn add_tab(tabs: HWND, index: usize, title: &str) {
    let mut text = utf16_nul(title);
    let item = TCITEMW {
        mask: TCIF_TEXT,
        dwState: TAB_CONTROL_ITEM_STATE(0),
        dwStateMask: TAB_CONTROL_ITEM_STATE(0),
        pszText: PWSTR(text.as_mut_ptr()),
        cchTextMax: 0,
        iImage: 0,
        lParam: LPARAM(0),
    };
    send(tabs, TCM_INSERTITEMW, index, &raw const item as isize);
}

fn list_add(list: HWND, text: &str) {
    let wide = utf16_nul(text);
    send(list, LB_ADDSTRING, 0, wide.as_ptr() as isize);
}

fn set_text(hwnd: HWND, text: &str) {
    let wide = utf16_nul(text);
    send(hwnd, WM_SETTEXT, 0, wide.as_ptr() as isize);
}

fn set_font(hwnd: HWND, font: HFONT) {
    send(hwnd, WM_SETFONT, font.0 as usize, 1);
}

fn warn(text: &str) {
    let body = HSTRING::from(text);
    let caption = HSTRING::from("RefineID");
    let _ = unsafe { MessageBoxW(None, &body, &caption, MB_OK | MB_ICONWARNING) };
}

fn info(text: &str) {
    let body = HSTRING::from(text);
    let caption = HSTRING::from("RefineID");
    let _ = unsafe { MessageBoxW(None, &body, &caption, MB_OK | MB_ICONINFORMATION) };
}

#[allow(
    clippy::too_many_arguments,
    reason = "the child-window helper mirrors CreateWindowExW's parameter list; callers pass position, size, style, and id straight through"
)]
fn child(
    class: PCWSTR,
    title: &str,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    id: u16,
    instance: HINSTANCE,
) -> windows::core::Result<HWND> {
    let text = HSTRING::from(title);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            &text,
            style,
            x,
            y,
            width,
            height,
            Some(parent),
            Some(menu_id(id)),
            Some(instance),
            None,
        )
    }
}

const fn menu_id(id: u16) -> HMENU {
    HMENU(id as usize as *mut core::ffi::c_void)
}

fn message_font() -> HFONT {
    let mut metrics: NONCLIENTMETRICSW = unsafe { std::mem::zeroed() };
    metrics.cbSize = u32::try_from(size_of::<NONCLIENTMETRICSW>()).unwrap_or(u32::MAX);
    let _ = unsafe {
        SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            metrics.cbSize,
            Some((&raw mut metrics).cast::<core::ffi::c_void>()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    unsafe { CreateFontIndirectW(&raw const metrics.lfMessageFont) }
}

fn utf16_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
