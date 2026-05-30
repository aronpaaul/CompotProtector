#![allow(non_snake_case)]

mod cli;
mod protect;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cli::run(&argv));
}
