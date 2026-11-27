use encoding_rs::{
    Encoding, BIG5, EUC_KR, GB18030, IBM866, SHIFT_JIS, UTF_8, WINDOWS_1251, WINDOWS_1252,
    WINDOWS_1258, WINDOWS_874,
};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::error::{DandiError, Result};

/// Supported archive filename encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodingId {
    Utf8,
    Cp949,
    ShiftJis,
    Gb18030,
    Big5,
    Windows1251,
    Ibm866,
    Windows1252,
    Cp437,
    Windows1258,
    Windows874,
}

const ALL_ENCODINGS: &[EncodingId] = &[
    EncodingId::Utf8,
    EncodingId::Cp949,
    EncodingId::ShiftJis,
    EncodingId::Gb18030,
    EncodingId::Big5,
    EncodingId::Windows1251,
    EncodingId::Ibm866,
    EncodingId::Windows1252,
    EncodingId::Cp437,
    EncodingId::Windows1258,
    EncodingId::Windows874,
];

const LEGACY_CANDIDATES: &[EncodingId] = &[
    EncodingId::Cp949,
    EncodingId::ShiftJis,
    EncodingId::Gb18030,
    EncodingId::Big5,
    EncodingId::Windows1251,
    EncodingId::Ibm866,
    EncodingId::Windows1252,
    EncodingId::Cp437,
    EncodingId::Windows1258,
    EncodingId::Windows874,
];

/// Returns all encodings supported by Dandi.
pub fn supported_encodings() -> &'static [EncodingId] {
    ALL_ENCODINGS
}

impl EncodingId {
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Cp949 => "cp949",
            Self::ShiftJis => "shift_jis",
            Self::Gb18030 => "gb18030",
            Self::Big5 => "big5",
            Self::Windows1251 => "windows-1251",
            Self::Ibm866 => "ibm866",
            Self::Windows1252 => "windows-1252",
            Self::Cp437 => "cp437",
            Self::Windows1258 => "windows-1258",
            Self::Windows874 => "windows-874",
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        let norm = name.trim().to_ascii_lowercase().replace('_', "-");
        match norm.as_str() {
            "utf-8" | "utf8" => Ok(Self::Utf8),
            "cp949" | "euc-kr" | "euckr" | "ks-c-5601" | "korean" | "ms949" | "uhc" => {
                Ok(Self::Cp949)
            }
            "shift-jis" | "shiftjis" | "sjis" | "cp932" | "ms932" | "japanese" => {
                Ok(Self::ShiftJis)
            }
            "gb18030" | "gbk" | "gb2312" | "cp936" | "ms936" | "chinese" | "zh-cn" => {
                Ok(Self::Gb18030)
            }
            "big5" | "cp950" | "ms950" | "zh-tw" => Ok(Self::Big5),
            "windows-1251" | "cp1251" | "win1251" | "cyrillic" => Ok(Self::Windows1251),
            "ibm866" | "cp866" | "dos866" | "866" => Ok(Self::Ibm866),
            "windows-1252" | "cp1252" | "win1252" | "latin1" | "iso-8859-1" => {
                Ok(Self::Windows1252)
            }
            "cp437" | "ibm437" | "dos437" | "437" => Ok(Self::Cp437),
            "windows-1258" | "cp1258" | "win1258" | "vietnamese" => Ok(Self::Windows1258),
            "windows-874" | "cp874" | "win874" | "tis-620" | "thai" => Ok(Self::Windows874),
            _ => Err(DandiError::UnsupportedEncoding(name.to_string())),
        }
    }

    fn encoding_rs(self) -> Option<&'static Encoding> {
        match self {
            Self::Utf8 => Some(UTF_8),
            Self::Cp949 => Some(EUC_KR),
            Self::ShiftJis => Some(SHIFT_JIS),
            Self::Gb18030 => Some(GB18030),
            Self::Big5 => Some(BIG5),
            Self::Windows1251 => Some(WINDOWS_1251),
            Self::Ibm866 => Some(IBM866),
            Self::Windows1252 => Some(WINDOWS_1252),
            Self::Cp437 => None,
            Self::Windows1258 => Some(WINDOWS_1258),
            Self::Windows874 => Some(WINDOWS_874),
        }
    }

    fn from_encoding_rs(enc: &'static Encoding) -> Option<Self> {
        if enc == UTF_8 {
            Some(Self::Utf8)
        } else if enc == EUC_KR {
            Some(Self::Cp949)
        } else if enc == SHIFT_JIS {
            Some(Self::ShiftJis)
        } else if enc == GB18030 || enc == encoding_rs::GBK {
            Some(Self::Gb18030)
        } else if enc == BIG5 {
            Some(Self::Big5)
        } else if enc == WINDOWS_1251 {
            Some(Self::Windows1251)
        } else if enc == IBM866 {
            Some(Self::Ibm866)
        } else if enc == WINDOWS_1252 {
            Some(Self::Windows1252)
        } else if enc == WINDOWS_1258 {
            Some(Self::Windows1258)
        } else if enc == WINDOWS_874 {
            Some(Self::Windows874)
        } else {
            None
        }
    }

    /// Decodes raw bytes with this encoding, returning `(decoded_string, had_errors)`.
    pub fn decode_bytes(self, raw: &[u8]) -> (String, bool) {
        if self == Self::Cp437 {
            return (decode_cp437(raw), false);
        }
        if let Some(enc) = self.encoding_rs() {
            let (cow, had_errors) = enc.decode_without_bom_handling(raw);
            (cow.into_owned(), had_errors)
        } else {
            (String::from_utf8_lossy(raw).into_owned(), true)
        }
    }

    /// Encodes a Unicode string into this encoding (primarily used in tests/eval fixture builders).
    pub fn encode_str(self, text: &str) -> (Vec<u8>, bool) {
        if self == Self::Cp437 {
            return encode_cp437(text);
        }
        if let Some(enc) = self.encoding_rs() {
            let (cow, _, had_errors) = enc.encode(text);
            (cow.into_owned(), had_errors)
        } else {
            (text.as_bytes().to_vec(), false)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryEncodingFlags {
    pub utf8_bit11: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeSource {
    Bit11Utf8,
    InfoZipUnicodeExtra,
    ValidUtf8,
    LegacyCodepage(EncodingId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedName {
    pub path: String,
    pub source: DecodeSource,
    pub had_errors: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodingCandidate {
    pub encoding: EncodingId,
    pub score: f64,
    pub had_errors: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodingDetection {
    pub encoding: EncodingId,
    pub confidence: f64,
    pub candidates: Vec<EncodingCandidate>,
}

/// Normalizes a relative path for packing into a Golden ZIP:
/// - Applies Unicode NFC normalization (fixes macOS NFD Hangul, Japanese dakuten, Latin accents, Vietnamese)
/// - Converts `\` to POSIX `/`
/// - Collapses repeated `/` and strips leading `./` or `/`
pub fn normalize_for_pack(path: &str) -> String {
    let nfc: String = path.nfc().collect();
    let replaced = nfc.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for segment in replaced.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        parts.push(segment);
    }
    let mut joined = parts.join("/");
    if replaced.ends_with('/') && !joined.is_empty() {
        joined.push('/');
    }
    joined
}

/// Detects the most likely legacy encoding across all raw entry names in an archive.
///
/// Never relies on process locale (`LC_CTYPE`); operates solely on raw byte slices.
pub fn detect_archive_encoding(
    raw_names: &[&[u8]],
    locale_hint: Option<EncodingId>,
) -> EncodingDetection {
    let mut corpus = Vec::new();
    let mut non_utf8_count = 0usize;

    for raw in raw_names {
        let has_high = raw.iter().any(|&b| b >= 0x80);
        if !has_high {
            continue;
        }
        if std::str::from_utf8(raw).is_ok() {
            continue;
        }
        non_utf8_count += 1;
        if !corpus.is_empty() {
            corpus.push(b'\n');
        }
        corpus.extend_from_slice(raw);
    }

    if non_utf8_count == 0 {
        return EncodingDetection {
            encoding: EncodingId::Utf8,
            confidence: 1.0,
            candidates: vec![EncodingCandidate {
                encoding: EncodingId::Utf8,
                score: 1.0,
                had_errors: false,
            }],
        };
    }

    let mut detector = chardetng::EncodingDetector::new();
    detector.feed(&corpus, true);
    let (chardet_enc, chardet_high_conf) = detector.guess_assess(None, true);
    let chardet_id = EncodingId::from_encoding_rs(chardet_enc);

    let mut scored: Vec<EncodingCandidate> = LEGACY_CANDIDATES
        .iter()
        .map(|&enc| {
            let (decoded, had_errors) = enc.decode_bytes(&corpus);
            let mut score = score_decoded_corpus(enc, &corpus, &decoded, had_errors);
            if Some(enc) == chardet_id && !had_errors {
                score += if chardet_high_conf { 65.0 } else { 35.0 };
            }
            if Some(enc) == locale_hint && !had_errors {
                score += 6.0;
            }
            EncodingCandidate {
                encoding: enc,
                score,
                had_errors,
            }
        })
        .collect();

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let best = scored
        .first()
        .map(|c| c.encoding)
        .unwrap_or(EncodingId::Utf8);
    let top_score = scored.first().map(|c| c.score).unwrap_or(0.0);
    let second_score = scored.get(1).map(|c| c.score).unwrap_or(0.0);
    let margin = (top_score - second_score).max(0.0);
    let confidence = if top_score <= 0.0 {
        0.25
    } else {
        (0.5 + (margin / (top_score.abs() + 20.0)) * 0.5).clamp(0.25, 0.99)
    };

    EncodingDetection {
        encoding: best,
        confidence,
        candidates: scored,
    }
}

/// Decodes an archive entry name using the 3-tier priority rule:
/// 1. Bit 11 UTF-8 flag
/// 2. Info-ZIP `0x7075` Unicode Path extra field (only if `NameCRC32 == crc32(raw)`)
/// 3. Valid UTF-8 check (unless an explicit non-UTF-8 encoding is forced on non-ASCII bytes)
/// 4. `forced` / corpus-detected legacy codepage
///
/// Output is always normalized to Unicode NFC.
pub fn decode_entry_name(
    raw: &[u8],
    flags: EntryEncodingFlags,
    unicode_extra_0x7075: Option<&[u8]>,
    forced: EncodingId,
) -> DecodedName {
    if flags.utf8_bit11 {
        if let Ok(s) = std::str::from_utf8(raw) {
            return DecodedName {
                path: s.nfc().collect(),
                source: DecodeSource::Bit11Utf8,
                had_errors: false,
            };
        }
    }

    if let Some(extra) = unicode_extra_0x7075 {
        if let Some(unicode_name) = verify_0x7075(raw, extra) {
            return DecodedName {
                path: unicode_name.nfc().collect(),
                source: DecodeSource::InfoZipUnicodeExtra,
                had_errors: false,
            };
        }
    }

    if let Ok(s) = std::str::from_utf8(raw) {
        return DecodedName {
            path: s.nfc().collect(),
            source: DecodeSource::ValidUtf8,
            had_errors: false,
        };
    }

    let (decoded, had_errors) = forced.decode_bytes(raw);
    DecodedName {
        path: decoded.nfc().collect(),
        source: DecodeSource::LegacyCodepage(forced),
        had_errors,
    }
}

/// Verifies an Info-ZIP `0x7075` Unicode Path Extra Field payload against raw header bytes.
///
/// Format: `Version (1 byte, must be 1) | NameCRC32 (4 bytes LE) | UnicodeName (UTF-8 bytes)`.
pub fn verify_0x7075<'a>(raw_name: &[u8], extra_payload: &'a [u8]) -> Option<&'a str> {
    if extra_payload.len() < 5 {
        return None;
    }
    if extra_payload[0] != 1 {
        return None;
    }
    let expected_crc = u32::from_le_bytes([
        extra_payload[1],
        extra_payload[2],
        extra_payload[3],
        extra_payload[4],
    ]);
    let actual_crc = crc32fast::hash(raw_name);
    if actual_crc != expected_crc {
        return None;
    }
    std::str::from_utf8(&extra_payload[5..]).ok()
}

fn score_decoded_corpus(enc: EncodingId, raw: &[u8], decoded: &str, had_errors: bool) -> f64 {
    let mut score = if had_errors { -250.0 } else { 20.0 };

    let mut non_ascii = 0usize;
    let mut hangul = 0usize;
    let mut hiragana_katakana = 0usize;
    let mut halfwidth_katakana = 0usize;
    let mut cjk = 0usize;
    let mut cyrillic = 0usize;
    let mut cyrillic_basic = 0usize;
    let mut latin_ext = 0usize;
    let mut thai = 0usize;
    let mut viet_comb_or_ext = 0usize;
    let mut box_drawing = 0usize;
    let mut replacement = 0usize;
    let mut suspicious_symbols = 0usize;
    let mut control_chars = 0usize;

    let chars: Vec<char> = decoded.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        if ch.is_ascii() {
            if (ch as u32) < 0x20 && ch != '\n' {
                control_chars += 1;
            }
            continue;
        }
        non_ascii += 1;
        let cp = ch as u32;
        match cp {
            0xFFFD => replacement += 1,
            0x0080..=0x009F => control_chars += 1,
            0xAC00..=0xD7A3 => hangul += 1,
            0x3040..=0x30FF => hiragana_katakana += 1,
            0xFF61..=0xFF9F => halfwidth_katakana += 1,
            0x4E00..=0x9FFF => cjk += 1,
            0x0400..=0x04FF => {
                cyrillic += 1;
                if matches!(cp, 0x0410..=0x044F | 0x0401 | 0x0451) {
                    cyrillic_basic += 1;
                }
            }
            0x00C0..=0x00FF if cp != 0x00D7 && cp != 0x00F7 => {
                latin_ext += 1;
                // Bonus when flanked by ASCII letters (typical European filename like café/über/niño)
                let prev_ascii_alpha = idx > 0 && chars[idx - 1].is_ascii_alphabetic();
                let next_ascii_alpha =
                    idx + 1 < chars.len() && chars[idx + 1].is_ascii_alphabetic();
                if prev_ascii_alpha || next_ascii_alpha {
                    score += 6.0;
                }
            }
            0x0E00..=0x0E7F => thai += 1,
            0x0300..=0x036F
            | 0x1E00..=0x1EFF
            | 0x0102
            | 0x0103
            | 0x0110
            | 0x0111
            | 0x01A0
            | 0x01A1
            | 0x01AF
            | 0x01B0 => viet_comb_or_ext += 1,
            0x2500..=0x259F => box_drawing += 1,
            0xE000..=0xFAFF => suspicious_symbols += 2,
            _ => suspicious_symbols += 1,
        }
    }

    // Penalize replacement characters, control characters, and box-drawing artifacts heavily
    score -= (replacement as f64) * 60.0;
    score -= (control_chars as f64) * 40.0;
    score -= (box_drawing as f64) * 28.0;
    score -= (suspicious_symbols as f64) * 8.0;

    // Penalize mixed Latin-ASCII + Cyrillic letters directly adjacent inside the same token
    // (classic artifact when Windows-1252 accented European words are decoded as Windows-1251)
    let mut mixed_latin_cyrillic = 0usize;
    for pair in chars.windows(2) {
        let a_lat = pair[0].is_ascii_alphabetic();
        let b_lat = pair[1].is_ascii_alphabetic();
        let a_cyr = matches!(pair[0] as u32, 0x0400..=0x04FF);
        let b_cyr = matches!(pair[1] as u32, 0x0400..=0x04FF);
        if (a_lat && b_cyr) || (a_cyr && b_lat) {
            mixed_latin_cyrillic += 1;
        }
    }
    score -= (mixed_latin_cyrillic as f64) * 18.0;

    // Check if high bytes are mostly isolated single bytes (strong signal for single-byte codepages)
    let mut isolated_high_bytes = 0usize;
    let mut paired_high_bytes = 0usize;
    for i in 0..raw.len() {
        if raw[i] >= 0x80 {
            let prev_high = i > 0 && raw[i - 1] >= 0x80;
            let next_high = i + 1 < raw.len() && raw[i + 1] >= 0x80;
            if !prev_high && !next_high {
                isolated_high_bytes += 1;
            } else {
                paired_high_bytes += 1;
            }
        }
    }

    // Penalize swallowed ASCII path separators or dots in DBCS decoders (e.g. Windows-1252 `é.` eaten as DBCS)
    let raw_slashes = raw.iter().filter(|&&b| b == b'/' || b == b'.').count();
    let decoded_slashes = decoded.chars().filter(|&c| c == '/' || c == '.').count();
    if decoded_slashes < raw_slashes {
        score -= ((raw_slashes - decoded_slashes) as f64) * 35.0;
    }

    match enc {
        EncodingId::Cp949 => {
            score += (hangul as f64) * 24.0;
            score += (cjk as f64) * 4.0;
            if hangul == 0 && non_ascii > 0 {
                score -= 25.0;
            }
        }
        EncodingId::ShiftJis => {
            score += (hiragana_katakana as f64) * 26.0;
            score += (cjk as f64) * 14.0;
            // Half-width katakana spam is a notorious false positive when CP949/GBK is read as Shift_JIS
            score -= (halfwidth_katakana as f64) * 16.0;
            // Bonus for genuine Shift_JIS 0x5C trail bytes that decoded cleanly into Kanji/Katakana
            let sjis_5c_pairs = count_sjis_5c_pairs(raw);
            if !had_errors && sjis_5c_pairs > 0 && (hiragana_katakana > 0 || cjk > 0) {
                score += (sjis_5c_pairs as f64) * 18.0;
            }
        }
        EncodingId::Gb18030 => {
            score += (cjk as f64) * 16.0;
            if cjk == 0 && non_ascii > 0 {
                score -= 20.0;
            }
        }
        EncodingId::Big5 => {
            score += (cjk as f64) * 16.0;
            if cjk == 0 && non_ascii > 0 {
                score -= 20.0;
            }
        }
        EncodingId::Windows1251 => {
            score += (cyrillic_basic as f64) * 9.5;
            score -= ((cyrillic - cyrillic_basic) as f64) * 12.0;
            if cyrillic_basic == 0 && non_ascii > 0 {
                score -= 30.0;
            }
        }
        EncodingId::Ibm866 => {
            score += (cyrillic_basic as f64) * 9.5;
            score -= ((cyrillic - cyrillic_basic) as f64) * 12.0;
            if cyrillic_basic == 0 && non_ascii > 0 {
                score -= 30.0;
            }
        }
        EncodingId::Windows1252 => {
            score += (latin_ext as f64) * 9.0;
            if isolated_high_bytes > 0 && paired_high_bytes == 0 {
                score += 20.0;
            }
            if latin_ext == 0 && non_ascii > 0 {
                score -= 25.0;
            }
        }
        EncodingId::Cp437 => {
            score += (latin_ext as f64) * 5.0;
            // Prefer Windows-1252 unless CP437 has clean Latin accents without box drawing
            score -= 5.0;
        }
        EncodingId::Windows1258 => {
            score += (viet_comb_or_ext as f64) * 8.0;
            score += (latin_ext as f64) * 4.0;
            if viet_comb_or_ext == 0 {
                score -= 20.0;
            }
        }
        EncodingId::Windows874 => {
            // Single-byte Thai maps almost every 0xA1..0xFB byte to U+0E00..0x0E7F;
            // check Thai orthographic validity (combining marks must follow a Thai consonant).
            let invalid_thai = count_invalid_thai_sequences(&chars);
            score += (thai as f64) * 5.5;
            score -= (invalid_thai as f64) * 20.0;
            if thai == 0 && non_ascii > 0 {
                score -= 30.0;
            }
        }
        EncodingId::Utf8 => {}
    }

    score
}

fn count_invalid_thai_sequences(chars: &[char]) -> usize {
    let mut bad = 0usize;
    let mut prev_is_consonant = false;
    for &ch in chars {
        let cp = ch as u32;
        let is_consonant = (0x0E01..=0x0E2E).contains(&cp);
        let is_combining = matches!(cp, 0x0E31 | 0x0E34..=0x0E3A | 0x0E47..=0x0E4E);
        if is_combining && !prev_is_consonant {
            bad += 1;
        }
        // Thai digits or rare symbols mixed randomly inside filenames
        if matches!(cp, 0x0E3B..=0x0E3F | 0x0E4F..=0x0E5B) {
            bad += 1;
        }
        prev_is_consonant = is_consonant;
    }
    bad
}

fn count_sjis_5c_pairs(raw: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i + 1 < raw.len() {
        let b = raw[i];
        if (0x81..=0x9F).contains(&b) || (0xE0..=0xFC).contains(&b) {
            if raw[i + 1] == 0x5C {
                count += 1;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}

#[rustfmt::skip]
const CP437_HIGH: [char; 128] = [
    '\u{00C7}', '\u{00FC}', '\u{00E9}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E5}', '\u{00E7}',
    '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00EF}', '\u{00EE}', '\u{00EC}', '\u{00C4}', '\u{00C5}',
    '\u{00C9}', '\u{00E6}', '\u{00C6}', '\u{00F4}', '\u{00F6}', '\u{00F2}', '\u{00FB}', '\u{00F9}',
    '\u{00FF}', '\u{00D6}', '\u{00DC}', '\u{00A2}', '\u{00A3}', '\u{00A5}', '\u{20A7}', '\u{0192}',
    '\u{00E1}', '\u{00ED}', '\u{00F3}', '\u{00FA}', '\u{00F1}', '\u{00D1}', '\u{00AA}', '\u{00BA}',
    '\u{00BF}', '\u{2310}', '\u{00AC}', '\u{00BD}', '\u{00BC}', '\u{00A1}', '\u{00AB}', '\u{00BB}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{255C}', '\u{255B}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}', '\u{255E}', '\u{255F}',
    '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256C}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256B}',
    '\u{256A}', '\u{2518}', '\u{250C}', '\u{2588}', '\u{2584}', '\u{258C}', '\u{2590}', '\u{2580}',
    '\u{03B1}', '\u{00DF}', '\u{0393}', '\u{03C0}', '\u{03A3}', '\u{03C3}', '\u{00B5}', '\u{03C4}',
    '\u{03A6}', '\u{0398}', '\u{03A9}', '\u{03B4}', '\u{221E}', '\u{03C6}', '\u{03B5}', '\u{2229}',
    '\u{2261}', '\u{00B1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00F7}', '\u{2248}',
    '\u{00B0}', '\u{2219}', '\u{00B7}', '\u{221A}', '\u{207F}', '\u{00B2}', '\u{25A0}', '\u{00A0}',
];

fn decode_cp437(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for &b in raw {
        if b < 0x80 {
            out.push(b as char);
        } else {
            out.push(CP437_HIGH[(b - 0x80) as usize]);
        }
    }
    out
}

fn encode_cp437(text: &str) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(text.len());
    let mut had_errors = false;
    for ch in text.chars() {
        if (ch as u32) < 0x80 {
            out.push(ch as u8);
        } else if let Some(pos) = CP437_HIGH.iter().position(|&c| c == ch) {
            out.push(0x80 + pos as u8);
        } else {
            out.push(b'?');
            had_errors = true;
        }
    }
    (out, had_errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_normalization::UnicodeNormalization;

    #[test]
    fn normalize_nfd_to_nfc_and_posix() {
        let nfd: String = "가나다라_보고서\\がぎぐ\\café_Tiếng_Việt.txt"
            .nfd()
            .collect();
        let packed = normalize_for_pack(&format!("./{nfd}"));
        assert_eq!(packed, "가나다라_보고서/がぎぐ/café_Tiếng_Việt.txt");
        assert_eq!(packed, packed.nfc().collect::<String>());
    }

    #[test]
    fn detect_cp949_corpus() {
        let names = [
            "보고서_최종.txt",
            "가나다라/회의록_2026.pdf",
            "사진_모음.jpg",
        ];
        let encoded: Vec<Vec<u8>> = names
            .iter()
            .map(|s| EncodingId::Cp949.encode_str(s).0)
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(|v| v.as_slice()).collect();
        let det = detect_archive_encoding(&refs, None);
        assert_eq!(det.encoding, EncodingId::Cp949);
    }

    #[test]
    fn detect_shift_jis_with_5c_bytes() {
        let names = [
            "一覧表_機能一覧.txt",
            "ソフト設計書/能力確認.md",
            "予定表.csv",
        ];
        let encoded: Vec<Vec<u8>> = names
            .iter()
            .map(|s| EncodingId::ShiftJis.encode_str(s).0)
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(|v| v.as_slice()).collect();
        let det = detect_archive_encoding(&refs, None);
        assert_eq!(det.encoding, EncodingId::ShiftJis);
        let decoded = decode_entry_name(refs[0], EntryEncodingFlags::default(), None, det.encoding);
        assert_eq!(decoded.path, "一覧表_機能一覧.txt");
    }

    #[test]
    fn detect_gb18030_and_big5() {
        let sc_names = [
            "项目报告_最终版.docx",
            "数据分析/年度总结.xlsx",
            "系统说明.txt",
        ];
        let sc_enc: Vec<Vec<u8>> = sc_names
            .iter()
            .map(|s| EncodingId::Gb18030.encode_str(s).0)
            .collect();
        let sc_refs: Vec<&[u8]> = sc_enc.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            detect_archive_encoding(&sc_refs, None).encoding,
            EncodingId::Gb18030
        );

        let tc_names = [
            "專案報告_最終版.docx",
            "資料分析/年度總結.xlsx",
            "系統說明書.txt",
        ];
        let tc_enc: Vec<Vec<u8>> = tc_names
            .iter()
            .map(|s| EncodingId::Big5.encode_str(s).0)
            .collect();
        let tc_refs: Vec<&[u8]> = tc_enc.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            detect_archive_encoding(&tc_refs, None).encoding,
            EncodingId::Big5
        );
    }

    #[test]
    fn detect_cyrillic_and_western() {
        let ru_names = ["Отчет_финал.txt", "Документы/проверка_данных.pdf"];
        let w1251: Vec<Vec<u8>> = ru_names
            .iter()
            .map(|s| EncodingId::Windows1251.encode_str(s).0)
            .collect();
        let w1251_refs: Vec<&[u8]> = w1251.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            detect_archive_encoding(&w1251_refs, None).encoding,
            EncodingId::Windows1251
        );

        let cp866: Vec<Vec<u8>> = ru_names
            .iter()
            .map(|s| EncodingId::Ibm866.encode_str(s).0)
            .collect();
        let cp866_refs: Vec<&[u8]> = cp866.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            detect_archive_encoding(&cp866_refs, None).encoding,
            EncodingId::Ibm866
        );

        let west = ["café_résumé.txt", "über_niño_Ångström.md"];
        let w1252: Vec<Vec<u8>> = west
            .iter()
            .map(|s| EncodingId::Windows1252.encode_str(s).0)
            .collect();
        let w1252_refs: Vec<&[u8]> = w1252.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            detect_archive_encoding(&w1252_refs, None).encoding,
            EncodingId::Windows1252
        );
    }

    #[test]
    fn verify_0x7075_honors_valid_and_rejects_tampered() {
        let raw = EncodingId::Cp949.encode_str("보고서.txt").0;
        let crc = crc32fast::hash(&raw);
        let mut valid = Vec::new();
        valid.push(1u8);
        valid.extend_from_slice(&crc.to_le_bytes());
        valid.extend_from_slice("보고서_유니코드.txt".as_bytes());

        let dec = decode_entry_name(
            &raw,
            EntryEncodingFlags { utf8_bit11: false },
            Some(&valid),
            EncodingId::Cp949,
        );
        assert_eq!(dec.source, DecodeSource::InfoZipUnicodeExtra);
        assert_eq!(dec.path, "보고서_유니코드.txt");

        let mut tampered = valid.clone();
        tampered[1] ^= 0xFF;
        let dec2 = decode_entry_name(
            &raw,
            EntryEncodingFlags { utf8_bit11: false },
            Some(&tampered),
            EncodingId::Cp949,
        );
        assert_eq!(dec2.source, DecodeSource::LegacyCodepage(EncodingId::Cp949));
        assert_eq!(dec2.path, "보고서.txt");
    }
}
