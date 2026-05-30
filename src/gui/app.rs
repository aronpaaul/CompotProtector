use super::{fonts, runner, theme, view};
use crate::protect::ProtectionOptions;
use std::sync::mpsc::Receiver;

pub enum Msg {
    Progress(f32, String),
    Done(Result<String, String>),
}

pub struct GuiApp {
    pub inputPath: String,
    pub outputPath: String,
    pub options: ProtectionOptions,
    pub progress: f32,
    pub statusNote: String,
    pub running: bool,
    pub result: Option<Result<String, String>>,
    pub rx: Option<Receiver<Msg>>,
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        fonts::install(&cc.egui_ctx);
        theme::apply(&cc.egui_ctx);
        Self {
            inputPath: String::new(),
            outputPath: String::new(),
            options: ProtectionOptions::default(),
            progress: 0.0,
            statusNote: "Idle".into(),
            running: false,
            result: None,
            rx: None,
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        runner::poll(self);
        view::render(self, ctx);
        if self.running {
            ctx.request_repaint();
        }
    }
}

pub fn launch() {
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([740.0, 620.0])
            .with_min_inner_size([660.0, 540.0]),
        ..Default::default()
    };
    let _ = eframe::run_native("ComProtector", native, Box::new(|cc| Box::new(GuiApp::new(cc))));
}
