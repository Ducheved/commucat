use blake3::Hasher;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::util::encode_hex;

const MAX_AVATAR_SIZE: usize = 5 * 1024 * 1024; // 5 MB
const ALLOWED_MIME_TYPES: &[&str] = &["image/jpeg", "image/png", "image/webp", "image/gif"];

#[derive(Debug)]
pub enum UploadError {
    TooLarge,
    InvalidMimeType,
    Io(std::io::Error),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "file too large"),
            Self::InvalidMimeType => write!(f, "invalid mime type"),
            Self::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for UploadError {}

impl From<std::io::Error> for UploadError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Validates image data
pub fn validate_avatar(data: &[u8], mime_type: &str) -> Result<(), UploadError> {
    if data.len() > MAX_AVATAR_SIZE {
        return Err(UploadError::TooLarge);
    }

    if !ALLOWED_MIME_TYPES.contains(&mime_type) {
        return Err(UploadError::InvalidMimeType);
    }

    Ok(())
}

/// Generates a unique filename for uploaded file
pub fn generate_filename(data: &[u8], mime_type: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let hex = encode_hex(hash.as_bytes());

    let extension = match mime_type {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/webp" => "webp",
        "image/gif" => "gif",
        _ => "bin",
    };

    format!("{}.{}", &hex[..16], extension)
}

/// Saves uploaded file to disk
pub async fn save_file(uploads_dir: &str, filename: &str, data: &[u8]) -> Result<(), UploadError> {
    // Ensure uploads directory exists
    fs::create_dir_all(uploads_dir).await.map_err(|e| {
        tracing::error!(
            "failed to create uploads directory '{}': {}",
            uploads_dir,
            e
        );
        UploadError::Io(e)
    })?;

    let path = PathBuf::from(uploads_dir).join(filename);
    tracing::debug!("saving file to: {}", path.display());

    let mut file = fs::File::create(&path).await.map_err(|e| {
        tracing::error!("failed to create file '{}': {}", path.display(), e);
        UploadError::Io(e)
    })?;

    file.write_all(data).await.map_err(|e| {
        tracing::error!("failed to write file '{}': {}", path.display(), e);
        UploadError::Io(e)
    })?;

    file.flush().await.map_err(|e| {
        tracing::error!("failed to flush file '{}': {}", path.display(), e);
        UploadError::Io(e)
    })?;

    tracing::info!("file saved successfully: {}", path.display());
    Ok(())
}

/// Reads file from disk
pub async fn read_file(uploads_dir: &str, filename: &str) -> Result<Vec<u8>, UploadError> {
    let path = PathBuf::from(uploads_dir).join(filename);

    // Security: prevent path traversal
    if !path.starts_with(uploads_dir) {
        return Err(UploadError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path traversal detected",
        )));
    }

    let data = fs::read(&path).await?;
    Ok(data)
}

/// Gets MIME type from filename extension
pub fn mime_type_from_filename(filename: &str) -> &'static str {
    if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
        "image/jpeg"
    } else if filename.ends_with(".png") {
        "image/png"
    } else if filename.ends_with(".webp") {
        "image/webp"
    } else if filename.ends_with(".gif") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}
