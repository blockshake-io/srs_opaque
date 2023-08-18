pub enum InternalError {
    /// Custom error
    Custom(&'static str),
    /// Key-stretching error
    KsfError,
}
