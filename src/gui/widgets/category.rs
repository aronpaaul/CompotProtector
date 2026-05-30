use crate::gui::theme::{LINE, PANEL};
use egui::{FontFamily, FontId, Frame, Margin, RichText, Rounding, Stroke, Ui};

pub fn card(ui: &mut Ui, title: &str, body: impl FnOnce(&mut Ui)) {
    Frame::none()
        .fill(PANEL)
        .rounding(Rounding::same(14.0))
        .stroke(Stroke::new(1.0, LINE))
        .inner_margin(Margin::same(16.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let font = FontId::new(15.0, FontFamily::Name("medium".into()));
            ui.label(RichText::new(title).font(font));
            ui.add_space(8.0);
            body(ui);
        });
}
