//! Development aid: walks the app through its main states with a real
//! (test) account and saves a PNG of the Hushjar window after each, then
//! quits. It captures only this window's own rendering, never the screen.
//!
//! Build with `--features snapshot`, point HUSHJAR_DATA_DIR at a data folder
//! with a signed-in test account, and set HUSHJAR_SNAPSHOT_DIR and
//! HUSHJAR_SNAPSHOT_PASSWORD (the test account's password).

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};

use crate::{AppWindow, LoginRequestData, SignInForm, UnlockData};

/// A step: its file name, what to do, and how long to wait before capturing.
type Step = (&'static str, fn(&AppWindow), u64);

fn password() -> slint::SharedString {
    std::env::var("HUSHJAR_SNAPSHOT_PASSWORD")
        .unwrap_or_default()
        .into()
}

/// A sign-in form at `stage`, filled as the app would fill it, for the
/// stages that need a server to reach.
fn form(stage: i32, provider_index: i32, key_waiting: bool) -> SignInForm {
    let strings = |list: &[&str]| {
        ModelRc::new(VecModel::from(
            list.iter()
                .map(|s| (*s).into())
                .collect::<Vec<slint::SharedString>>(),
        ))
    };
    SignInForm {
        stage,
        server_choice: 2,
        url: "https://vault.example.org".into(),
        email: "sam@example.org".into(),
        providers: strings(&["Authenticator", "Email", "YubiKey", "Security key"]),
        provider_index,
        kinds: ModelRc::new(VecModel::from(vec![0, 1, 2, 3])),
        email_hint: "s**@example.org".into(),
        key_ready: true,
        key_waiting,
        phrase: "unlit-cobalt-saddle-tremor-amply".into(),
        ..SignInForm::default()
    }
}

const STEPS: &[Step] = &[
    ("01-locked", |_| {}, 800),
    ("02-unlocked", |w| w.invoke_unlock(password()), 5000),
    (
        "03-item",
        |w| {
            w.set_filter_text("github".into());
            w.invoke_filter_edited("github".into());
            w.invoke_filter_accepted();
        },
        800,
    ),
    ("04-edit", |w| w.invoke_begin_edit(), 800),
    (
        "05-tree",
        |w| {
            w.invoke_cancel();
            w.set_filter_text("".into());
            w.invoke_filter_edited("".into());
        },
        800,
    ),
    ("06-types", |w| w.invoke_group_by_picked(2), 800),
    ("06b-settings", |w| w.invoke_open_settings(), 800),
    ("06c-generator", |w| w.invoke_open_generator(), 800),
    ("06d-transfer", |w| w.invoke_open_transfer(), 800),
    ("06d-sends", |w| w.invoke_open_sends(), 800),
    (
        "06e-send-selected",
        |w| w.global::<crate::SendsData>().invoke_select(0),
        800,
    ),
    (
        "07-add-account",
        |w| {
            w.invoke_group_by_picked(0);
            w.invoke_add_account();
        },
        800,
    ),
    (
        "07a-add-account-email",
        |w| w.set_sign_in(form(0, 0, false)),
        500,
    ),
    (
        "07b-two-step-email",
        |w| w.set_sign_in(form(1, 1, false)),
        500,
    ),
    (
        "07c-two-step-yubikey",
        |w| w.set_sign_in(form(1, 2, false)),
        500,
    ),
    ("07d-security-key", |w| w.set_sign_in(form(1, 3, true)), 500),
    ("07e-new-device", |w| w.set_sign_in(form(2, 0, false)), 500),
    (
        "07f-device-login",
        |w| w.set_sign_in(form(3, 0, false)),
        500,
    ),
    (
        "07g-login-request",
        |w| {
            let data = w.global::<LoginRequestData>();
            data.set_account("sam@example.org".into());
            data.set_origin("Windows at 192.0.2.4".into());
            data.set_phrase("unlit-cobalt-saddle-tremor-amply".into());
            data.set_more(1);
            data.set_visible(true);
        },
        500,
    ),
    // Leaves time for an SSH signing request from outside, then allows it.
    (
        "08-ssh-prompt",
        |w| w.global::<LoginRequestData>().set_visible(false),
        4000,
    ),
    ("09-ssh-allowed", |w| w.invoke_ssh_answer(true), 800),
    // Back to the account pane, with its fingerprint phrase.
    ("09b-account", |w| w.invoke_sign_in_cancel(), 1500),
    ("10-locked-again", |w| w.invoke_lock_all(), 1500),
    (
        "10b-locked-pin",
        |w| w.global::<UnlockData>().set_pin_available(true),
        500,
    ),
];

pub fn run(window: &AppWindow, dir: PathBuf) -> Rc<Timer> {
    std::fs::create_dir_all(&dir).expect("create snapshot directory");
    let timer = Rc::new(Timer::default());
    let step = Rc::new(Cell::new(0usize));
    schedule(&timer, window.as_weak(), dir, step, 1500);
    timer
}

/// Runs the next step after `delay`, then captures it after its own wait.
fn schedule(
    timer: &Rc<Timer>,
    weak: slint::Weak<AppWindow>,
    dir: PathBuf,
    step: Rc<Cell<usize>>,
    delay: u64,
) {
    let next = timer.clone();
    timer.start(
        TimerMode::SingleShot,
        Duration::from_millis(delay),
        move || {
            let Some(w) = weak.upgrade() else { return };
            let Some((name, action, wait)) = STEPS.get(step.get()) else {
                let _ = slint::quit_event_loop();
                return;
            };
            action(&w);
            let (weak2, dir2, step2, timer2) =
                (weak.clone(), dir.clone(), step.clone(), next.clone());
            next.start(
                TimerMode::SingleShot,
                Duration::from_millis(*wait),
                move || {
                    if let Some(w) = weak2.upgrade() {
                        capture(&w, &dir2, name);
                    }
                    step2.set(step2.get() + 1);
                    schedule(&timer2, weak2.clone(), dir2.clone(), step2.clone(), 200);
                },
            );
        },
    );
}

fn capture(w: &AppWindow, dir: &std::path::Path, name: &str) {
    match w.window().take_snapshot() {
        Ok(buffer) => {
            let path = dir.join(format!("{name}.png"));
            match save_png(&path, &buffer) {
                Ok(()) => eprintln!("saved {}", path.display()),
                Err(err) => eprintln!("snapshot {name}: {err}"),
            }
        }
        Err(err) => eprintln!("snapshot {name}: {err}"),
    }
}

fn save_png(
    path: &std::path::Path,
    buffer: &slint::SharedPixelBuffer<slint::Rgba8Pixel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut encoder = png::Encoder::new(file, buffer.width(), buffer.height());
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()?
        .write_image_data(buffer.as_bytes())?;
    Ok(())
}
