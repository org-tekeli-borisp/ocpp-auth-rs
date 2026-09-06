fn main() {
    let password = std::env::args().nth(1).expect("password argument is required");
    println!("{}", bcrypt::hash(password.as_bytes(), 10).expect("hash password"));
}
