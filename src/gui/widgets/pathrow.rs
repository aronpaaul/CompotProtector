use egui::{TextEdit, Ui};

pub fn row(ui: &mut Ui, label: &str, value: &mut String, save: bool) {
    ui.label(label);
    ui.horizontal(|ui| {
        let browseWidth = 96.0;
        let editWidth = (ui.available_width() - browseWidth - 12.0).max(120.0);
        ui.add(TextEdit::singleline(value).desired_width(editWidth).hint_text("path to .exe"));
        if ui.button("Browse").clicked() {
            pick(value, save);
        }
    });
}

fn pick(value: &mut String, save: bool) {
    let dialog = rfd::FileDialog::new().add_filter("Executable", &["exe"]);
    let chosen = if save { dialog.save_file() } else { dialog.pick_file() };
    if let Some(path) = chosen {
        *value = path.display().to_string();
    }
}
