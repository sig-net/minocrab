//! The version of each of our crates is written down TWICE, and nothing but
//! this test makes the two copies agree: the crate's own version (inherited
//! from `[workspace.package] version`, or its own literal for an interface
//! crate), and a `version = "…"` beside the `path` of its entry in
//! `[workspace.dependencies]`.
//!
//! THE FAILURE CLASS IS POST-FIRST-PUBLISH SILENT RESOLUTION. Today a stale
//! requirement is invisible — nothing of ours is on crates.io, so cargo has
//! only the path to resolve against and the number beside it is decoration.
//! The day the first `cargo publish` lands, that number becomes the thing
//! cargo matches: bump `[workspace.package]` to 0.2.0 without bumping the
//! requirements and every sibling dependency resolves to the REGISTRY's 0.1.0
//! instead of the crate sitting next to it. The build succeeds, the tests
//! pass, and half the workspace is being compiled against a published copy of
//! its own past. There is no error message for that, so there is a test.
//!
//! The second test holds the publish rules of PUBLISHING.md for every crate
//! that does not carry `publish = false`: a regular dependency on one of our
//! crates goes through `[workspace.dependencies]` (where the version is) and
//! names a crate that is itself published; a dev-dependency on one of our
//! crates is a plain versionless `{ path = … }`, which cargo strips on
//! publish (that is what opens the minocrab-std ↔ minocrab-sim dev cycle).
//!
//! Line parsing rather than a toml crate: `toml` is not a dependency of this
//! workspace and one line of these manifests is one dependency entry. If that
//! stops being true, the not-vacuous assertions below fail rather than the
//! checks going quietly vacuous.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The workspace root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A manifest, with its path for the failure messages.
fn manifest(path: PathBuf) -> (PathBuf, String) {
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
    (path, text)
}

/// The workspace manifest, with its path for the failure messages.
fn workspace_manifest() -> (PathBuf, String) {
    manifest(root().join("Cargo.toml"))
}

/// The string a `key = "…"` on one manifest line carries, if it carries one.
///
/// `key` is matched as a whole word, so `rust-version` is not a `version`.
fn string_value(line: &str, key: &str) -> Option<String> {
    let mut rest = line;
    loop {
        let at = rest.find(key)?;
        let before_is_word = rest[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        let after = &rest[at + key.len()..];
        if !before_is_word && after.trim_start().starts_with('=') {
            let quoted = after.trim_start().trim_start_matches('=').trim_start();
            let value = quoted.strip_prefix('"')?;
            let end = value.find('"')?;
            return Some(value[..end].to_string());
        }
        rest = after;
    }
}

/// The name a manifest line declares: everything left of its first `=`.
fn entry_name(line: &str) -> &str {
    line.split('=').next().unwrap_or_default().trim()
}

/// The meaningful lines of a manifest, each with the `[section]` it is in.
fn lines_by_section(text: &str) -> Vec<(String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            section = trimmed.to_string();
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push((section.clone(), trimmed.to_string()));
    }
    out
}

/// `[workspace.package] version`.
fn workspace_version(path: &Path, text: &str) -> String {
    lines_by_section(text)
        .into_iter()
        .find(|(s, l)| s == "[workspace.package]" && entry_name(l) == "version")
        .and_then(|(_, l)| string_value(&l, "version"))
        .unwrap_or_else(|| {
            panic!(
                "{}: no `version = \"…\"` in [workspace.package] — every crate inherits it \
                 with `version.workspace = true`, so it has to be there",
                path.display()
            )
        })
}

/// One crate of ours, as its manifest declares it.
struct Member {
    manifest: PathBuf,
    text: String,
    /// The crate's version: its own literal, or the workspace's if inherited.
    version: String,
    published: bool,
}

/// Every crate under `crates/`, by package name.
fn members(workspace_version: &str) -> BTreeMap<String, Member> {
    let mut out = BTreeMap::new();
    let dir = root().join("crates");
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("a directory entry").path().join("Cargo.toml");
        if !path.exists() {
            continue;
        }
        let (path, text) = manifest(path);
        let mut name = None;
        let mut version = None;
        let mut published = true;
        for (section, line) in lines_by_section(&text) {
            if section != "[package]" {
                continue;
            }
            match entry_name(&line) {
                "name" => name = string_value(&line, "name"),
                "version" => version = string_value(&line, "version"),
                "version.workspace" => version = Some(workspace_version.to_string()),
                "publish" if line.contains("false") => published = false,
                _ => {}
            }
        }
        let name = name.unwrap_or_else(|| panic!("{}: no [package] name", path.display()));
        let version =
            version.unwrap_or_else(|| panic!("{}: no [package] version", path.display()));
        out.insert(name, Member { manifest: path, text, version, published });
    }
    out
}

/// Every `version = "…"` in `[workspace.dependencies]` that belongs to one of
/// OUR crates is that crate's own version: `[workspace.package] version` for
/// every crate that inherits it, the crate's literal for one that does not
/// (`signet-signer-interface`, versioned by its callee's wire format).
///
/// Upstream requirements (`borsh = { version = "1.6", … }`) are deliberately
/// out of scope: what is checked is the entries carrying `path =
/// "crates/…"`, which are the ones that resolve to this workspace today and to
/// the registry tomorrow.
#[test]
fn our_workspace_dependencies_carry_the_workspace_version() {
    let (path, text) = workspace_manifest();
    let package_version = workspace_version(&path, &text);
    let members = members(&package_version);

    let entries: Vec<(String, Option<String>)> = lines_by_section(&text)
        .into_iter()
        .filter(|(s, l)| s == "[workspace.dependencies]" && l.contains("path = \"crates/"))
        .map(|(_, l)| (entry_name(&l).to_string(), string_value(&l, "version")))
        .collect();

    // Not vacuous: the manifest has every crate the others depend on as a
    // path+version entry, and a parse that finds none has stopped working.
    assert!(
        !entries.is_empty(),
        "{}: no `path = \"crates/…\"` entry was parsed out of [workspace.dependencies]. \
         The manifest's shape moved (a multi-line inline table, most likely) and this test \
         reads nothing — fix the parse, do not delete the check",
        path.display()
    );

    for (name, version) in &entries {
        let own = members.get(name).map(|m| m.version.clone()).unwrap_or_else(|| {
            panic!(
                "{}: [workspace.dependencies] {name} points into crates/, but no crate \
                 there is named {name}",
                path.display()
            )
        });
        let version = version.as_deref().unwrap_or_else(|| {
            panic!(
                "{}: [workspace.dependencies] {name} has a `path` and no `version`. \
                 A path-only dependency cannot be published — crates.io resolves the version \
                 requirement and ignores the path — so add `version = \"{own}\"`",
                path.display()
            )
        });
        assert_eq!(
            version,
            own,
            "{}: [workspace.dependencies] {name} requires version \"{version}\", but \
             {name}'s own version is \"{own}\". THESE ARE ONE NUMBER. \
             Once {name} is on crates.io, cargo resolves this requirement against the \
             REGISTRY — the sibling crate in this workspace is used only if its version \
             satisfies it — so a stale requirement builds the workspace against a published \
             copy of its own past, silently. Bump both places together",
            path.display()
        );
    }
}

/// For every crate without `publish = false`: each regular or build
/// dependency on one of our crates is `name.workspace = true` or
/// `{ workspace = true, … }` (so it carries
/// the version from `[workspace.dependencies]`) and names a published crate;
/// each dev-dependency on one of our crates is a versionless path.
#[test]
fn published_crates_depend_only_on_published_crates() {
    let (path, text) = workspace_manifest();
    let members = members(&workspace_version(&path, &text));
    let mut checked = 0;

    for (crate_name, member) in members.iter().filter(|(_, m)| m.published) {
        for (section, line) in lines_by_section(&member.text) {
            let regular = section == "[dependencies]" || section == "[build-dependencies]";
            let dev = section == "[dev-dependencies]";
            if !regular && !dev {
                continue;
            }
            let name = entry_name(&line);
            let name = name.strip_suffix(".workspace").unwrap_or(name);
            let Some(dep) = members.get(name) else {
                continue;
            };
            assert!(
                !line.contains('{') || line.contains('}'),
                "{}: `{line}` is a multi-line inline table; this test reads one line per \
                 dependency — keep it on one line",
                member.manifest.display()
            );
            checked += 1;
            if regular {
                assert!(
                    line.contains("workspace = true") && !line.contains("path"),
                    "{}: {crate_name} is published, and `{line}` is a regular dependency on \
                     our crate {name} that does not go through [workspace.dependencies]. \
                     Write `{name}.workspace = true`, so the requirement carries the version \
                     crates.io resolves",
                    member.manifest.display()
                );
                assert!(
                    dep.published,
                    "{}: {crate_name} is published but depends on {name}, which carries \
                     `publish = false`. Either {name} joins the set (PUBLISHING.md) or the \
                     dependency becomes a dev-dependency",
                    member.manifest.display()
                );
            } else {
                assert!(
                    string_value(&line, "version").is_none() && !line.contains("workspace"),
                    "{}: `{line}` is a dev-dependency on our crate {name} with a version. \
                     Dev-dependencies on our crates stay plain `{{ path = \"…\" }}`: cargo \
                     strips a versionless dev-dependency on publish, which is what keeps the \
                     dev-dependency cycles (minocrab-std ↔ minocrab-sim) out of the registry",
                    member.manifest.display()
                );
            }
        }
    }

    // Not vacuous: the published crates depend on each other dozens of times.
    assert!(
        checked > 10,
        "only {checked} dependency edges between our crates were parsed out of the published \
         manifests; the parse has stopped reading them — fix it, do not delete the check"
    );
}
