use std::io::Write;

const WIDTH: usize = 28;

pub struct Bar;

impl Bar {
    pub fn new() -> Self {
        println!("ComProtector  ::  command-line protection");
        Bar
    }

    pub fn update(&mut self, fraction: f32, note: &str) {
        let pct = (fraction * 100.0).round() as u32;
        let filled = (fraction * WIDTH as f32).round() as usize;
        let filled = filled.min(WIDTH);
        let bar: String = "#".repeat(filled) + &"-".repeat(WIDTH - filled);
        print!("\r[{bar}] {pct:3}%  {note:<34}");
        let _ = std::io::stdout().flush();
    }

    pub fn finish(&mut self) {
        println!();
    }
}
