//! cwd → 프로젝트 루트. 위로 올라가며 표지 파일이 처음 나오는 폴더(홈과 / 는 루트로 치지 않는다).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub(crate) const MARKERS: &[&str] = &[
    ".git",
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
];

/// 파일 시스템 조회(테스트에서 가짜로 바꾼다).
pub(crate) trait FsProbe {
    fn has_marker(&self, dir: &str) -> bool;
}

pub(crate) struct RealFs;

impl FsProbe for RealFs {
    fn has_marker(&self, dir: &str) -> bool {
        let d = Path::new(dir);
        MARKERS
            .iter()
            .any(|m| std::fs::symlink_metadata(d.join(m)).is_ok())
    }
}

fn parent(dir: &str) -> Option<&str> {
    let trimmed = dir.trim_end_matches('/');
    let idx = trimmed.rfind('/')?;
    Some(if idx == 0 { "/" } else { &trimmed[..idx] })
}

pub(crate) fn project_roots<'a>(
    cwds: impl IntoIterator<Item = &'a str>,
    home: &str,
    fs: &dyn FsProbe,
) -> BTreeMap<String, String> {
    let home = home.trim_end_matches('/');
    let mut memo: HashMap<String, Option<String>> = HashMap::new();
    let mut out = BTreeMap::new();
    for cwd in cwds {
        if !cwd.starts_with('/') || cwd.starts_with("/Volumes/") || cwd.starts_with("/dev/") {
            continue;
        }
        if let Some(found) = memo.get(cwd) {
            if let Some(root) = found {
                out.insert(cwd.to_string(), root.clone());
            }
            continue;
        }
        let mut visited: Vec<String> = Vec::new();
        let mut dir = cwd.trim_end_matches('/');
        if dir.is_empty() {
            dir = "/";
        }
        let result = loop {
            if dir == "/" || (!home.is_empty() && dir == home) {
                break None;
            }
            if let Some(found) = memo.get(dir) {
                break found.clone();
            }
            visited.push(dir.to_string());
            if fs.has_marker(dir) {
                break Some(dir.to_string());
            }
            match parent(dir) {
                Some(p) => dir = p,
                None => break None,
            }
        };
        for v in visited {
            memo.insert(v, result.clone());
        }
        memo.entry(cwd.to_string())
            .or_insert_with(|| result.clone());
        if let Some(root) = result {
            out.insert(cwd.to_string(), root);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn roots_nearest_marker() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let shop = home.join("dev/shop");
        std::fs::create_dir_all(shop.join("web/src")).unwrap();
        std::fs::create_dir(shop.join(".git")).unwrap();
        std::fs::write(shop.join("web/package.json"), "{}").unwrap();
        std::fs::create_dir_all(home.join("dev/plain")).unwrap();
        let src = shop.join("web/src").to_string_lossy().into_owned();
        let other = shop.to_string_lossy().into_owned();
        let plain = home.join("dev/plain").to_string_lossy().into_owned();
        let roots = project_roots(
            [src.as_str(), other.as_str(), plain.as_str()],
            &home.to_string_lossy(),
            &RealFs,
        );
        assert_eq!(roots[&src], shop.join("web").to_string_lossy());
        assert_eq!(roots[&other], shop.to_string_lossy());
        assert!(!roots.contains_key(&plain));
    }

    #[test]
    fn roots_stops_at_home_and_slash() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(home.join("notes")).unwrap();
        std::fs::create_dir(home.join(".git")).unwrap();
        let notes = home.join("notes").to_string_lossy().into_owned();
        let h = home.to_string_lossy().into_owned();
        let roots = project_roots([notes.as_str(), h.as_str(), "/"], &h, &RealFs);
        assert!(roots.is_empty());
    }

    struct Fake {
        markers: HashSet<&'static str>,
        calls: RefCell<Vec<String>>,
    }

    impl FsProbe for Fake {
        fn has_marker(&self, dir: &str) -> bool {
            self.calls.borrow_mut().push(dir.to_string());
            self.markers.contains(dir)
        }
    }

    #[test]
    fn roots_memoized() {
        let fake = Fake {
            markers: HashSet::from(["/Users/demo/dev/shop"]),
            calls: RefCell::new(Vec::new()),
        };
        let cwds: Vec<String> = (0..10)
            .map(|i| format!("/Users/demo/dev/shop/pkg{i}/src"))
            .collect();
        let roots = project_roots(cwds.iter().map(String::as_str), "/Users/demo", &fake);
        assert_eq!(roots.len(), 10);
        assert!(roots.values().all(|r| r == "/Users/demo/dev/shop"));
        let calls = fake.calls.borrow();
        let unique: HashSet<&String> = calls.iter().collect();
        assert_eq!(unique.len(), calls.len(), "폴더마다 표지 검사는 한 번");
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.as_str() == "/Users/demo/dev/shop")
                .count(),
            1
        );
    }

    #[test]
    fn roots_skip_volumes_and_relative() {
        let fake = Fake {
            markers: HashSet::from(["/Volumes/ext/x"]),
            calls: RefCell::new(Vec::new()),
        };
        let roots = project_roots(["/Volumes/ext/x", "relative/dir"], "/Users/demo", &fake);
        assert!(roots.is_empty());
        assert!(fake.calls.borrow().is_empty());
    }
}
