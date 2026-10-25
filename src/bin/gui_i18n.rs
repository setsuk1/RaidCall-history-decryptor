//! GUI interface text, loaded from bundled UTF-8 INI resources.
//! The language catalogs are shipped with the executable, so installation
//! never depends on locating additional files at runtime.

use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Language { English, TraditionalChinese }

impl Language {
    pub(crate) fn code(self) -> &'static str {
        match self { Self::English => "en", Self::TraditionalChinese => "zh-TW" }
    }

    pub(crate) fn from_code(code: &str) -> Self {
        if code.eq_ignore_ascii_case("zh-TW") { Self::TraditionalChinese }
        else { Self::English }
    }

    pub(crate) fn from_system() -> Self {
        let locale = std::env::var("LC_ALL").ok().filter(|s| !s.is_empty())
            .or_else(|| std::env::var("LANG").ok())
            .unwrap_or_default().to_lowercase();
        if locale.starts_with("zh") { Self::TraditionalChinese } else { Self::English }
    }

    pub(crate) fn tr(self, key: &str) -> &'static str {
        static EN: OnceLock<HashMap<String, String>> = OnceLock::new();
        static ZH_TW: OnceLock<HashMap<String, String>> = OnceLock::new();
        let english = EN.get_or_init(|| parse_ini(include_str!("../../assets/i18n/en.ini")));
        match self {
            Self::English => english.get(key),
            Self::TraditionalChinese => {
                let chinese = ZH_TW.get_or_init(|| {
                    parse_ini(include_str!("../../assets/i18n/zh-TW.ini"))
                });
                chinese.get(key).or_else(|| english.get(key))
            }
        }.map(String::as_str).unwrap_or("[missing translation]")
    }
}

// Parse the [strings] section from a UTF-8 INI file. The first '=' is the
// separator; values (including Windows paths and percent signs) are literal.
fn parse_ini(input: &str) -> HashMap<String, String> {
    let mut strings = HashMap::new();
    let mut in_strings = false;
    for line in input.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_strings = line.eq_ignore_ascii_case("[strings]");
            continue;
        }
        if in_strings {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                if !key.is_empty() {
                    strings.insert(key.to_owned(), value.trim().to_owned());
                }
            }
        }
    }
    strings
}

// Load an installed operating-system CJK font for egui.
pub(crate) fn configure_fonts(ctx: &eframe::egui::Context) {
    use eframe::egui::{FontData, FontDefinitions, FontFamily};
    use std::{fs, path::PathBuf, sync::Arc};
    let candidates: &[&str] = if cfg!(target_os = "windows") {
        &[
            "C:/Windows/Fonts/msjh.ttc",
            "C:/Windows/Fonts/msjhl.ttc",
            "C:/Windows/Fonts/mingliu.ttc",
            "C:/Windows/Fonts/simsun.ttc",
        ]
    } else {
        &[
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJKtc-Regular.otf",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        ]
    };
    let mut defs = FontDefinitions::default();
    for path in candidates {
        let candidate = PathBuf::from(path);
        if let Ok(data) = fs::read(&candidate) {
            if data.len() > 25_000_000 { continue; }
            defs.font_data.insert("system_cjk".into(), Arc::new(FontData::from_owned(data)));
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                defs.families.entry(family).or_default().insert(0, "system_cjk".into());
            }
            ctx.set_fonts(defs);
            return;
        }
    }
    eprintln!("RaidCall GUI: no CJK font found; Chinese glyphs may be missing");
}
