use super::app::{GuiApp, Msg};
use crate::protect;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

pub fn start(app: &mut GuiApp) {
    if app.running {
        return;
    }
    let (tx, rx) = mpsc::channel();
    app.rx = Some(rx);
    app.running = true;
    app.progress = 0.0;
    app.result = None;
    app.statusNote = "Starting".into();

    let input = PathBuf::from(&app.inputPath);
    let output = PathBuf::from(&app.outputPath);
    let opts = app.options.clone();

    thread::spawn(move || {
        let mut sink = |fraction: f32, note: &str| {
            let _ = tx.send(Msg::Progress(fraction, note.to_string()));
        };
        let outcome = protect::protect(&input, &output, &opts, &mut sink)
            .map(|report| report.summary())
            .map_err(|err| err.to_string());
        let _ = tx.send(Msg::Done(outcome));
    });
}

pub fn poll(app: &mut GuiApp) {
    let mut drained = Vec::new();
    if let Some(rx) = &app.rx {
        while let Ok(msg) = rx.try_recv() {
            drained.push(msg);
        }
    }
    let mut finished = false;
    for msg in drained {
        match msg {
            Msg::Progress(fraction, note) => {
                app.progress = fraction;
                app.statusNote = note;
            }
            Msg::Done(result) => {
                app.statusNote = if result.is_ok() { "Completed" } else { "Failed" }.into();
                app.result = Some(result);
                app.running = false;
                finished = true;
            }
        }
    }
    if finished {
        app.rx = None;
    }
}
