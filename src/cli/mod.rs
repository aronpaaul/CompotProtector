mod args;
mod bar;

use crate::protect;

pub fn run(argv: &[String]) -> i32 {
    attachConsole();
    if argv.is_empty() || argv.iter().any(|a| a == "--help" || a == "-h") {
        printHelp();
        return 0;
    }
    let parsed = match args::parse(argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}\nrun with --help for usage");
            return 2;
        }
    };
    let mut bar = bar::Bar::new();
    let mut sink = |fraction: f32, note: &str| bar.update(fraction, note);
    let result = protect::protect(&parsed.input, &parsed.output, &parsed.options, &mut sink);
    bar.finish();
    match result {
        Ok(report) => {
            println!("{}", report.summary());
            0
        }
        Err(e) => {
            eprintln!("failed: {e}");
            1
        }
    }
}

fn printHelp() {
    println!(
        "ComProtector — PE protector (CLI)\n\n\
USAGE:\n  \
comprotector -i <input.exe> -o <output.exe> [options]\n\n\
OPTIONS:\n  \
-i, --input <path>      input executable\n  \
-o, --output <path>     protected output executable\n  \
--no-symbols            keep COFF symbol table\n  \
--no-debug-sections     keep .debug_* sections\n  \
--no-strings            do not encrypt strings\n  \
--no-reencrypt          disable runtime re-encryption thread\n  \
--zero-strings          keep string memory zeroed (shows 0000 in dumps)\n  \
--min-len <n>           minimum string length (default 3)\n  \
--interval <ms>         string re-encryption period (default 1500)\n  \
--window <ms>           string re-encrypted window (default 40)\n  \
--no-hide-imports       keep the import table (do not hide imports)\n  \
--reencrypt-imports     re-encrypt the IAT in runtime (best-effort, risky)\n  \
--import-interval <ms>  import re-encryption period (default 2000)\n  \
--import-window <ms>    import re-encrypted window (default 12)\n  \
--no-anti-debug         disable the anti-debugger checks\n  \
--anti-vm               exit if a hypervisor / sandbox is detected (opt-in)\n  \
--no-virtualize         disable code virtualization of marked regions\n  \
--no-encrypt-code       do not encrypt the .text section (every function)\n  \
--lazy                  lazy mode: decrypt .text on-demand via VEH (anti-dump)\n  \
--lazy-interval <ms>    lazy re-encryption period (default 50)\n  \
--no-watermark          do not stamp the CompotProtector watermark\n  \
-h, --help              show this help"
    );
}

#[cfg(windows)]
fn attachConsole() {
    extern "system" {
        fn AttachConsole(processId: u32) -> i32;
    }
    unsafe {
        AttachConsole(0xFFFF_FFFF);
    }
}

#[cfg(not(windows))]
fn attachConsole() {}
