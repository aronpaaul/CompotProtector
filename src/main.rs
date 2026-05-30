#![allow(non_snake_case)]
#![cfg_attr(feature = "gui", windows_subsystem = "windows")]

mod mode;
mod protect;
mod cli;
#[cfg(feature = "gui")]
mod gui;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if mode::wantsCli(&argv) {
        std::process::exit(cli::run(&argv));
    }
    #[cfg(feature = "gui")]
    {
        gui::launch();
    }
    #[cfg(not(feature = "gui"))]
    {
        eprintln!("GUI feature disabled. Use CLI arguments, see --help.");
        std::process::exit(2);
    }
}
