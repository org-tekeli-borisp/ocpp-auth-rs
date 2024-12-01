pub mod utils {
    use std::any::type_name;

    pub fn type_of<T>(_: &T) -> &str {
        type_name::<T>()
    }
}