use rand::{distributions::Alphanumeric, Rng};

fn main() {
    let random_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    println!("cargo:rustc-env=OBFSTR_SEED={}", random_string);
}
