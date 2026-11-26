//! Development aid: walks the prototype through its main states and saves a
//! PNG of the Hushjar window after each one, then quits. It captures only this
//! window's own rendering, never the rest of the screen.
//!
//! Build with `--features snapshot` and set `HUSHJAR_SNAPSHOT_DIR`.

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use slint::{ComponentHandle, Timer, TimerMode};

use crate::AppWindow;

type Step = (&'static str, fn(&AppWindow));

const STEPS: &[Step] = &[
    ("01-item", |_| {}),
    ("02-edit", |w| w.invoke_begin_edit()),
    ("03-filter", |w| {
        w.invoke_cancel();
        w.set_filter_text("git".into());
        w.invoke_filter_edited("git".into());
    }),
    ("04-collections", |w| {
        w.set_filter_text("".into());
        w.invoke_filter_edited("".into());
        w.invoke_group_by_picked(1);
        w.invoke_row_clicked("w/o/Example Ltd".into());
    }),
    ("05-locked", |w| {
        w.invoke_group_by_picked(0);
        w.invoke_row_clicked("f".into());
    }),
    ("06-card", |w| {
        w.invoke_row_toggled("p/f/Finance".into());
        w.invoke_row_clicked("p/f/Finance/i/visa".into());
    }),
    ("07-leave-guard", |w| {
        w.invoke_begin_edit();
        w.invoke_edit_name("Everyday Visa card".into());
        w.invoke_row_clicked("p/f/Finance/i/bank".into());
    }),
];

pub fn run(window: &AppWindow, dir: PathBuf) -> Timer {
    std::fs::create_dir_all(&dir).expect("create snapshot directory");
    let weak = window.as_weak();
    let step = Rc::new(Cell::new(0usize));
    let timer = Timer::default();
    // Odd ticks apply a step, even ticks capture it once it has rendered.
    timer.start(TimerMode::Repeated, Duration::from_millis(700), move || {
        let Some(w) = weak.upgrade() else { return };
        let tick = step.get();
        step.set(tick + 1);
        let index = tick / 2;
        let Some((name, action)) = STEPS.get(index) else {
            let _ = slint::quit_event_loop();
            return;
        };
        if tick.is_multiple_of(2) {
            action(&w);
            return;
        }
        match w.window().take_snapshot() {
            Ok(buffer) => {
                let path = dir.join(format!("{name}.png"));
                if let Err(err) = save_png(&path, &buffer) {
                    eprintln!("snapshot {name}: {err}");
                } else {
                    eprintln!("saved {}", path.display());
                }
            }
            Err(err) => eprintln!("snapshot {name}: {err}"),
        }
    });
    timer
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
