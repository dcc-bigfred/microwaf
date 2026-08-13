//! Version metadata (ELF section + build env).

use std::sync::OnceLock;

/// ELF section name for release injection.
#[allow(dead_code)]
pub const SECTION_NAME: &str = ".microwaf.version";

/// Public version payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Release tag or `"dev"`.
    pub version: String,
    /// Build git commit.
    pub commit: String,
    /// Build time.
    pub build_time: String,
}

static INFO: OnceLock<Info> = OnceLock::new();

/// Cached version info.
#[must_use]
pub fn info() -> Info {
    INFO.get_or_init(|| Info {
        version: "dev".into(),
        commit: option_env!("MICROWAF_GIT_COMMIT")
            .unwrap_or("unknown")
            .into(),
        build_time: option_env!("MICROWAF_BUILD_TIME").unwrap_or("").into(),
    })
    .clone()
}
