use super::app::GuiApp;
use super::panels;
use super::widgets::bar;
use egui::{Color32, Context, FontFamily, FontId, RichText, ScrollArea, Ui};

pub fn render(app: &mut GuiApp, ctx: &Context) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ScrollArea::vertical().show(ui, |ui| {
            header(ui);
            ui.add_space(16.0);
            panels::files(app, ui);
            ui.add_space(10.0);
            panels::debug(app, ui);
            ui.add_space(10.0);
            panels::strings(app, ui);
            ui.add_space(10.0);
            panels::imports(app, ui);
            ui.add_space(16.0);
            panels::action(app, ui);
            ui.add_space(14.0);
            bar::draw(ui, app.progress);
            ui.add_space(8.0);
            footer(app, ui);
        });
    });
}

fn header(ui: &mut Ui) {
    let title = FontId::new(30.0, FontFamily::Name("display".into()));
    ui.label(RichText::new("ComProtector").font(title));
    ui.label(RichText::new("Debug stripping & runtime string obfuscation").weak());
}

fn footer(app: &GuiApp, ui: &mut Ui) {
    let line = format!("{:.0}%   ·   {}", app.progress * 100.0, app.statusNote);
    ui.label(RichText::new(line).weak());
    if let Some(result) = &app.result {
        ui.add_space(4.0);
        match result {
            Ok(text) => {
                ui.label(RichText::new(text).size(12.5));
            }
            Err(err) => {
                ui.colored_label(Color32::from_rgb(196, 42, 42), err);
            }
        }
    }
}
