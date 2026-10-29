use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::Engine;

const CHUNK: usize = 128 * 1024;
const MAX_FILE: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;

pub(super) fn findings(home: &Path) -> Vec<crate::Finding> {
    let patterns: Vec<String> = serde_json::from_str(include_str!("sources.json"))
        .expect("embedded eMudhra installation paths must be valid");
    scan(home, &patterns)
}

fn scan(home: &Path, patterns: &[String]) -> Vec<crate::Finding> {
    let mut paths = Vec::new();
    let mut errors = Vec::new();
    let mut visits = 4096usize;
    for pattern in patterns.iter().filter(|p| p.as_str() != super::CERT_PATH) {
        let path = pattern
            .strip_prefix("~/")
            .map(|p| home.join(p))
            .unwrap_or_else(|| PathBuf::from(pattern));
        expand(
            Path::new("/"),
            &path
                .components()
                .skip(1)
                .map(|p| p.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            &mut paths,
            &mut errors,
            &mut visits,
        );
    }
    let needles = needles();
    let mut seen = HashSet::new();
    let mut remaining = 2 * 1024 * 1024 * 1024u64;
    for path in paths {
        let resolved = match fs::canonicalize(&path) {
            Ok(path) => path,
            Err(error) => {
                errors.push(finding(
                    &path,
                    format!("Could not inspect installed trust source ({error})"),
                ));
                continue;
            }
        };
        if !seen.insert(resolved.clone()) {
            continue;
        }
        let bundle = path.extension().is_some_and(|ext| ext == "pem");
        let size = fs::metadata(&resolved).map(|m| m.len()).unwrap_or(0);
        if size > remaining {
            errors.push(finding(
                &resolved,
                "Scan byte budget exhausted; inspect remaining trust sources manually".into(),
            ));
            break;
        }
        remaining -= size;
        let result = inspect(&resolved, bundle, &needles, size);
        match result {
            Ok(roots) if !roots.is_empty() => errors.push(finding(&resolved, format!(
                "{} contains {} associated with eMudhra trust paths. Update the owning {} and rescan; {}",
                if bundle { "CA bundle" } else { "Runtime binary" }, roots.join(" and "),
                if bundle { "CA package" } else { "runtime package" },
                if bundle { "this package is not modified by av harden emudhra" }
                else { "embedded root material is a Hazard, not proof of effective runtime trust or compromise" }
            ))),
            Ok(_) => {},
            Err(error) => errors.push(finding(&resolved, format!("Could not inspect installed trust source ({error}); update or review the owning package"))),
        }
    }
    errors
}

fn finding(path: &Path, explanation: String) -> crate::Finding {
    crate::Finding {
        source: "emudhra",
        homepage: super::super::radioisotope::DETECTORS_URL,
        severity: "high",
        affected: vec![crate::AffectedFile {
            path: path.display().to_string(),
            line: None,
        }],
        explanation: format!("{explanation}: {}", path.display()),
        solution: super::super::detector_config("emudhra").solution.clone(),
        docs_url: super::super::radioisotope::DETECTORS_URL,
    }
}

// Only expand the catalog's shallow installation layouts; never crawl a user's home.
fn expand(
    base: &Path,
    parts: &[String],
    paths: &mut Vec<PathBuf>,
    errors: &mut Vec<crate::Finding>,
    visits: &mut usize,
) {
    if *visits == 0 {
        return;
    }
    *visits -= 1;
    if *visits == 0 {
        errors.push(finding(
            base,
            "Trust-source discovery limit reached; inspect remaining installations manually".into(),
        ));
        return;
    }
    let Some((part, rest)) = parts.split_first() else {
        match fs::symlink_metadata(base) {
            Ok(_) => paths.push(base.to_owned()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(e) => errors.push(finding(
                base,
                format!("Could not inspect trust-source path ({e})"),
            )),
        }
        return;
    };
    let Some((prefix, suffix)) = part.split_once('*') else {
        expand(&base.join(part), rest, paths, errors, visits);
        return;
    };
    match fs::read_dir(base) {
        Ok(entries) => {
            let mut children = Vec::new();
            for (index, entry) in entries.enumerate() {
                if index == MAX_ENTRIES {
                    errors.push(finding(base, "Trust-source discovery limit reached; inspect remaining installations manually".into()));
                    break;
                }
                match entry {
                    Ok(entry) => {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        if name.starts_with(prefix) && name.ends_with(suffix) {
                            children.push(entry.path());
                        }
                    }
                    Err(e) => errors.push(finding(
                        base,
                        format!("Could not enumerate trust sources ({e})"),
                    )),
                }
            }
            children.sort();
            for child in children {
                expand(&child, rest, paths, errors, visits);
            }
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) => {}
        Err(e) => errors.push(finding(
            base,
            format!("Could not enumerate trust sources ({e})"),
        )),
    }
}

fn needles() -> Vec<(usize, Vec<u8>)> {
    let mut needles = Vec::new();
    for (index, (pem, spki)) in [
        (
            include_str!("testdata/emsign.pem"),
            include_str!("testdata/emsign-spki.base64"),
        ),
        (
            include_str!("testdata/aaa.pem"),
            include_str!("testdata/aaa-spki.base64"),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let encoded: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        needles.push((
            index,
            base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .unwrap(),
        ));
        // webpki-roots stores SPKI contents without the outer ASN.1 SEQUENCE header.
        needles.push((
            index,
            base64::engine::general_purpose::STANDARD
                .decode(spki.trim())
                .unwrap(),
        ));
        for width in [64, 72, 76] {
            for newline in ["\n", "\r\n"] {
                let body = encoded
                    .as_bytes()
                    .chunks(width)
                    .map(|c| std::str::from_utf8(c).unwrap())
                    .collect::<Vec<_>>()
                    .join(newline);
                needles.push((index, body.into_bytes()));
            }
        }
    }
    needles
}

fn inspect(
    path: &Path,
    bundle: bool,
    needles: &[(usize, Vec<u8>)],
    allowance: u64,
) -> Result<Vec<&'static str>, String> {
    // O_NONBLOCK prevents an attacker-supplied FIFO from hanging a background Scan.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file".into());
    }
    let limit = (if bundle { 16 * 1024 * 1024 } else { MAX_FILE }).min(allowance);
    if metadata.len() > limit {
        return Err("file exceeds inspection size limit".into());
    }
    if bundle {
        let mut contents = String::new();
        file.take(limit + 1)
            .read_to_string(&mut contents)
            .map_err(|e| e.to_string())?;
        if contents.len() as u64 > limit {
            return Err("file grew beyond inspection size limit".into());
        }
        return super::filtered_bundle(&contents).map(|(_, roots)| roots);
    }
    scan_binary(&mut file, needles, limit)
}

fn scan_binary(
    reader: &mut impl Read,
    needles: &[(usize, Vec<u8>)],
    limit: u64,
) -> Result<Vec<&'static str>, String> {
    let overlap = needles.iter().map(|(_, n)| n.len()).max().unwrap() - 1;
    let mut buffer = vec![0; CHUNK + overlap];
    let mut retained = 0;
    let mut total = 0;
    let mut found = [false; 2];
    loop {
        let n = reader
            .read(&mut buffer[retained..retained + CHUNK.min((limit - total + 1) as usize)])
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > limit {
            return Err("file grew beyond inspection size limit".into());
        }
        let bytes = &buffer[..retained + n];
        for (index, needle) in needles {
            if !found[*index] && contains(bytes, needle) {
                found[*index] = true;
            }
        }
        let end = bytes.len();
        retained = overlap.min(end);
        buffer.copy_within(end - retained..end, 0);
    }
    Ok(super::ROOTS
        .iter()
        .enumerate()
        .filter(|(i, _)| found[*i])
        .map(|(_, (_, name))| *name)
        .collect())
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(bytes, needle).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("av-emudhra-sources-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, data: impl AsRef<[u8]>) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, data).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn matches_embedded_pem_der_and_webpki_anchors_across_chunks() {
        let needles = needles();
        for (index, needle) in &needles {
            let mut binary = vec![0xff; CHUNK - needle.len() / 2];
            binary.extend(needle);
            binary.extend([0, 0xfe, 0xff]);
            let roots = scan_binary(&mut binary.as_slice(), &needles, MAX_FILE).unwrap();
            assert_eq!(roots, vec![super::super::ROOTS[*index].1]);
        }
        let text = b"emSign ECC Root CA - G3 AAA Certificate Services";
        assert!(
            scan_binary(&mut text.as_slice(), &needles, MAX_FILE)
                .unwrap()
                .is_empty()
        );
        let safe = include_bytes!("testdata/unaffected.pem");
        assert!(
            scan_binary(&mut safe.as_slice(), &needles, MAX_FILE)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn discovers_inactive_versions_deduplicates_aliases_and_reports_exact_paths() {
        let f = Fixture::new();
        let old = f.write(
            ".nvm/versions/node/v20/bin/node",
            include_bytes!("testdata/emsign.pem"),
        );
        f.write(
            ".nvm/versions/node/v24/bin/node",
            include_bytes!("testdata/unaffected.pem"),
        );
        symlink(&old, f.0.join("node")).unwrap();
        f.write(".nvm/versions/node/.manager-metadata", []);
        let before = fs::read(&old).unwrap();
        let findings = scan(
            &f.0,
            &[
                "~/.nvm/versions/node/*/bin/node".into(),
                "~/node".into(),
                "~/absent".into(),
            ],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].affected[0].path,
            fs::canonicalize(&old).unwrap().display().to_string()
        );
        assert!(
            findings[0]
                .explanation
                .contains("Update the owning runtime package")
        );
        assert_eq!(fs::read(old).unwrap(), before);
    }

    #[test]
    fn bundle_errors_broken_links_and_special_files_are_not_clean() {
        let f = Fixture::new();
        f.write("cert.pem", b"invalid bundle");
        symlink(f.0.join("missing"), f.0.join("broken")).unwrap();
        fs::create_dir(f.0.join("node")).unwrap();
        let findings = scan(
            &f.0,
            &["~/cert.pem".into(), "~/broken".into(), "~/node".into()],
        );
        assert_eq!(findings.len(), 3);
        assert!(
            findings
                .iter()
                .all(|f| f.explanation.contains("Could not inspect"))
        );
        let fifo = f.0.join("fifo");
        let cpath = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(
            inspect(&fifo, false, &needles(), MAX_FILE)
                .unwrap_err()
                .contains("not a regular file")
        );
    }

    #[test]
    fn reports_oversize_files_and_discovery_limits() {
        let f = Fixture::new();
        let path = f.write("node", []);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_FILE + 1)
            .unwrap();
        assert!(
            inspect(&path, false, &needles(), MAX_FILE)
                .unwrap_err()
                .contains("size limit")
        );
        assert!(scan_binary(&mut [0u8; 10].as_slice(), &needles(), 5).is_err());
        for i in 0..=MAX_ENTRIES {
            f.write(&format!("versions/{i}/bin/node"), []);
        }
        assert!(
            scan(&f.0, &["~/versions/*/bin/node".into()])
                .iter()
                .any(|f| f.explanation.contains("discovery limit"))
        );
    }

    #[test]
    fn catalog_finds_default_runtimes_and_anchors_belong_to_pinned_certificates() {
        let f = Fixture::new();
        f.write(".deno/bin/deno", include_bytes!("testdata/emsign.pem"));
        f.write(".bun/bin/bun", include_bytes!("testdata/aaa.pem"));
        f.write(
            ".local/share/mise/installs/node/24/bin/node",
            include_bytes!("testdata/emsign.pem"),
        );
        let patterns: Vec<String> = serde_json::from_str(include_str!("sources.json")).unwrap();
        assert!(
            patterns
                .iter()
                .all(|p| p.starts_with('/') || p.starts_with("~/"))
        );
        let home_patterns = patterns
            .into_iter()
            .filter(|p| p.starts_with("~/"))
            .collect::<Vec<_>>();
        assert_eq!(scan(&f.0, &home_patterns).len(), 3);
        let needles = needles();
        for group in needles.chunks(8) {
            assert!(contains(&group[0].1, &group[1].1));
            let mut changed = group[1].1.clone();
            changed[20] ^= 1;
            assert!(
                scan_binary(&mut changed.as_slice(), &needles, MAX_FILE)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn detects_both_bundle_roots_without_modifying_them() {
        let f = Fixture::new();
        let contents = format!(
            "{}{}",
            include_str!("testdata/emsign.pem"),
            include_str!("testdata/aaa.pem")
        );
        let path = f.write("etc/ca-certificates/cert.pem", &contents);
        let result = scan(&f.0, &["~/etc/ca-certificates/cert.pem".into()]);
        assert_eq!(result.len(), 1);
        assert!(
            result[0]
                .explanation
                .contains("emSign ECC Root CA - G3 and AAA Certificate Services")
        );
        assert!(result[0].explanation.contains("owning CA package"));
        assert_eq!(fs::read_to_string(path).unwrap(), contents);
    }
}
