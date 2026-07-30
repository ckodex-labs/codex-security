use crate::error::SdkError;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanTarget {
    pub path: PathBuf,
    pub exists: bool,
    pub is_file: bool,
    pub is_dir: bool,
    pub normalized: String,
}

impl ScanTarget {
    pub fn from_path(path: &str) -> Result<Self> {
        let path_buf = PathBuf::from(path);
        let exists = path_buf.exists();
        let is_file = path_buf.is_file();
        let is_dir = path_buf.is_dir();

        let normalized = if exists {
            path_buf
                .canonicalize()
                .map(|p| p.to_string_lossy().to_string())?
        } else {
            path.to_string()
        };

        Ok(Self {
            path: path_buf,
            exists,
            is_file,
            is_dir,
            normalized,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !self.exists {
            return Err(SdkError::ScanError(format!(
                "Scan target does not exist: {}",
                self.path.display()
            ))
            .into());
        }

        if !self.is_file && !self.is_dir {
            return Err(SdkError::ScanError(format!(
                "Scan target is neither a file nor a directory: {}",
                self.path.display()
            ))
            .into());
        }

        Ok(())
    }

    pub fn display_name(&self) -> String {
        self.normalized.clone()
    }
}

pub fn prepare_target(target: &str) -> Result<ScanTarget> {
    let scan_target = ScanTarget::from_path(target)?;
    scan_target.validate()?;
    Ok(scan_target)
}
