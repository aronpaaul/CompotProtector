pub fn wantsCli(argv: &[String]) -> bool {
    if argv.iter().any(|a| a == "--gui") {
        return false;
    }
    !argv.is_empty()
}
