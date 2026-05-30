use egui::{Color32, Context, Rounding, Stroke, Visuals};

pub const INK: Color32 = Color32::from_rgb(18, 18, 20);
pub const WHITE: Color32 = Color32::from_rgb(255, 255, 255);
pub const PANEL: Color32 = Color32::from_rgb(247, 247, 248);
pub const LINE: Color32 = Color32::from_rgb(224, 224, 228);
const HOVER: Color32 = Color32::from_rgb(236, 236, 239);

pub fn apply(ctx: &Context) {
    let mut v = Visuals::light();
    let r = Rounding::same(12.0);
    v.override_text_color = Some(INK);
    v.panel_fill = WHITE;
    v.window_fill = WHITE;
    v.extreme_bg_color = PANEL;
    v.faint_bg_color = PANEL;

    v.widgets.noninteractive.rounding = r;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    v.widgets.inactive.rounding = r;
    v.widgets.inactive.weak_bg_fill = PANEL;
    v.widgets.inactive.bg_fill = PANEL;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, INK);
    v.widgets.hovered.rounding = r;
    v.widgets.hovered.weak_bg_fill = HOVER;
    v.widgets.hovered.bg_fill = HOVER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, INK);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, INK);
    v.widgets.active.rounding = r;
    v.widgets.active.weak_bg_fill = INK;
    v.widgets.active.bg_fill = INK;
    v.widgets.active.fg_stroke = Stroke::new(1.0, WHITE);
    v.selection.bg_fill = INK;
    v.selection.stroke = Stroke::new(1.0, WHITE);
    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(16.0, 9.0);
    ctx.set_style(style);
}
