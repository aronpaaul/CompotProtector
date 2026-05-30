use super::app::GuiApp;
use super::runner;
use super::widgets::{category, pathrow};
use egui::{Button, Checkbox, Slider, Ui};

pub fn files(app: &mut GuiApp, ui: &mut Ui) {
    category::card(ui, "Files", |ui| {
        pathrow::row(ui, "Input executable", &mut app.inputPath, false);
        ui.add_space(8.0);
        pathrow::row(ui, "Output executable", &mut app.outputPath, true);
    });
}

pub fn debug(app: &mut GuiApp, ui: &mut Ui) {
    category::card(ui, "Debug information", |ui| {
        ui.checkbox(&mut app.options.debug.stripSymbols, "Strip COFF symbol table");
        ui.checkbox(&mut app.options.debug.stripDebugSections, "Remove all .debug sections");
    });
}

pub fn strings(app: &mut GuiApp, ui: &mut Ui) {
    category::card(ui, "String obfuscation", |ui| {
        let on = app.options.strings.encrypt;
        ui.checkbox(&mut app.options.strings.encrypt, "Encrypt every string (decrypt at runtime)");
        let reenc = Checkbox::new(&mut app.options.strings.runtimeReencrypt, "Re-encrypt in runtime (background thread)");
        ui.add_enabled(on, reenc);
        ui.add_enabled(on, Checkbox::new(&mut app.options.strings.zeroize, "Zeroize strings in memory (shows 0000 in dumps)"));
        ui.add_space(6.0);
        ui.add(Slider::new(&mut app.options.strings.minLength, 3..=16).text("min length"));
        ui.add(Slider::new(&mut app.options.strings.intervalMs, 100..=5000).text("re-encrypt interval, ms"));
        ui.add(Slider::new(&mut app.options.strings.windowMs, 5..=500).text("encrypted window, ms"));
    });
}

pub fn imports(app: &mut GuiApp, ui: &mut Ui) {
    category::card(ui, "Imports & analysis hardening", |ui| {
        ui.checkbox(&mut app.options.antiDebug, "Anti-debug (terminate the process under a debugger)");
        ui.checkbox(&mut app.options.encryptCode, "Encrypt every function (.text encryption, runtime decrypt)");
        let enc = app.options.encryptCode;
        ui.add_enabled(enc, Checkbox::new(&mut app.options.lazy, "Lazy mode (VEH on-demand decrypt, anti-dump)"));
        ui.add_enabled(enc && app.options.lazy, Slider::new(&mut app.options.lazyIntervalMs, 10..=2000).text("lazy re-encrypt period, ms"));
        ui.checkbox(&mut app.options.virtualize, "Virtualize marked code regions (custom VM)");
        ui.checkbox(&mut app.options.imports.hide, "Hide all imports (hash-resolving, breaks IAT/RVA)");
        let on = app.options.imports.hide;
        let reenc = Checkbox::new(&mut app.options.imports.runtimeReencrypt, "Re-encrypt IAT in runtime (risky)");
        ui.add_enabled(on, reenc);
        ui.add_enabled(on, Slider::new(&mut app.options.imports.intervalMs, 200..=8000).text("IAT re-encrypt interval, ms"));
        ui.add_enabled(on, Slider::new(&mut app.options.imports.windowMs, 2..=200).text("IAT encrypted window, ms"));
    });
}

pub fn action(app: &mut GuiApp, ui: &mut Ui) {
    let ready = !app.inputPath.is_empty() && !app.outputPath.is_empty() && !app.running;
    let label = if app.running { "Protecting…" } else { "Protect executable" };
    if ui.add_enabled(ready, Button::new(label)).clicked() {
        runner::start(app);
    }
}
