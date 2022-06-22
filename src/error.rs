use std::fmt;

#[derive(Debug)]
pub enum BookmarkError {
    BadHeader,
    BadBookmarkData,
}

impl std::error::Error for BookmarkError {}

impl fmt::Display for BookmarkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BookmarkError::BadHeader => write!(f, "Incorrect bookmark header"),
            BookmarkError::BadBookmarkData => write!(f, "Failed to parse bookmark data"),
        }
    }
}
