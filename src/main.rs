mod utils;
mod hook32;
mod hook_usage;

fn main() {
    unsafe { hook_usage::set().unwrap() };
}
