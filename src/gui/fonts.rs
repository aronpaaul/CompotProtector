use egui::{Context, FontData, FontDefinitions, FontFamily};

static REGULAR: &[u8] = include_bytes!("../../assets/fonts/SFProDisplay-Regular.otf");
static MEDIUM: &[u8] = include_bytes!("../../assets/fonts/SFProDisplay-Medium.otf");
static BOLD: &[u8] = include_bytes!("../../assets/fonts/SFProDisplay-Bold.otf");

pub fn install(ctx: &Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("sfRegular".into(), FontData::from_static(REGULAR));
    fonts.font_data.insert("sfMedium".into(), FontData::from_static(MEDIUM));
    fonts.font_data.insert("sfBold".into(), FontData::from_static(BOLD));

    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "sfRegular".into());
    fonts.families.insert(FontFamily::Name("display".into()), vec!["sfBold".into()]);
    fonts.families.insert(FontFamily::Name("medium".into()), vec!["sfMedium".into()]);

    ctx.set_fonts(fonts);
}
