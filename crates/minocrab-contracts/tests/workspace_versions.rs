//! The workspace's own version is written down TWICE, and nothing but this
//! test makes the two copies agree: `[workspace.package] version`, and a
//! `version = "…"` beside the `path` of every one of our crates in
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
//! Line parsing rather than a toml crate: `toml` is not a dependency of this
//! workspace and one line of this manifest is one dependency entry. If that
//! stops being true, `entries_were_found` below fails rather than the check
//! going quietly vacuous.

/// The workspace manifest, with its path for the failure messages.
fn workspace_manifest() -> (std::path::PathBuf, String) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
    (path, text)
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

/// The name a `[workspace.dependencies]` line declares: everything left of
/// its first `=`.
fn entry_name(line: &str) -> &str {
    line.split('=').next().unwrap_or_default().trim()
}

/// Every `version = "…"` in `[workspace.dependencies]` that belongs to one of
/// OUR crates is `[workspace.package] version`.
///
/// Upstream requirements (`borsh = { version = "1.6", … }`) are deliberately
/// out of scope: what is checked is the entries carrying `path =
/// "crates/…"`, which are the ones that resolve to this workspace today and to
/// the registry tomorrow.
#[test]
fn our_workspace_dependencies_carry_the_workspace_version() {
    let (path, text) = workspace_manifest();
    let mut section = "";
    let mut package_version: Option<String> = None;
    let mut entries: Vec<(String, Option<String>)> = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            section = trimmed;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match section {
            "[workspace.package]" => {
                if entry_name(trimmed) == "version" {
                    package_version = string_value(trimmed, "version");
                }
            }
            "[workspace.dependencies]" => {
                if trimmed.contains("path = \"crates/") {
                    let name = entry_name(trimmed).to_string();
                    entries.push((name, string_value(trimmed, "version")));
                }
            }
            _ => {}
        }
    }

    let package_version = package_version.unwrap_or_else(|| {
        panic!(
            "{}: no `version = \"…\"` in [workspace.package] — every crate inherits it \
             with `version.workspace = true`, so it has to be there",
            path.display()
        )
    });

    // Not vacuous: the manifest has our seven crates as path+version entries,
    // and a parse that finds none is a parse that has stopped working.
    assert!(
        !entries.is_empty(),
        "{}: no `path = \"crates/…\"` entry was parsed out of [workspace.dependencies]. \
         The manifest's shape moved (a multi-line inline table, most likely) and this test \
         reads nothing — fix the parse, do not delete the check",
        path.display()
    );

    for (name, version) in &entries {
        let version = version.as_deref().unwrap_or_else(|| {
            panic!(
                "{}: [workspace.dependencies] {name} has a `path` and no `version`. \
                 A path-only dependency cannot be published — crates.io resolves the version \
                 requirement and ignores the path — so add `version = \"{package_version}\"`",
                path.display()
            )
        });
        assert_eq!(
            version,
            package_version,
            "{}: [workspace.dependencies] {name} requires version \"{version}\", but \
             [workspace.package] version is \"{package_version}\". THESE ARE ONE NUMBER. \
             Once {name} is on crates.io, cargo resolves this requirement against the \
             REGISTRY — the sibling crate in this workspace is used only if its version \
             satisfies it — so a stale requirement builds the workspace against a published \
             copy of its own past, silently. Bump both places together",
            path.display()
        );
    }
}
