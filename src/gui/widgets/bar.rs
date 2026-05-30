use crate::gui::theme::{INK, LINE};
use egui::{vec2, Rounding, Sense, Ui};

pub fn draw(ui: &mut Ui, fraction: f32) {
    let height = 14.0;
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    let painter = ui.painter();
    let rounding = Rounding::same(height / 2.0);
    painter.rect_filled(rect, rounding, LINE);

    let clamped = fraction.clamp(0.0, 1.0);
    if clamped > 0.0 {
        let mut fill = rect;
        fill.set_width((rect.width() * clamped).max(height));
        painter.rect_filled(fill, rounding, INK);
    }
}
