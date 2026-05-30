pub type ProgressFn<'a> = dyn FnMut(f32, &str) + 'a;

pub fn report(sink: &mut ProgressFn, fraction: f32, note: &str) {
    sink(fraction.clamp(0.0, 1.0), note);
}
