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

use slint::{ComponentHandle, Timer, TimerMode};

use crate::AppWindow;

/// A step: its file name, what to do, and how long to wait before capturing.
type Step = (&'static str, fn(&AppWindow), u64);

fn password() -> slint::SharedString {
    std::env::var("HUSHJAR_SNAPSHOT_PASSWORD")
        .unwrap_or_default()
        .into()
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
    (
        "07-add-account",
        |w| {
            w.invoke_group_by_picked(0);
            w.invoke_add_account();
        },
        800,
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
