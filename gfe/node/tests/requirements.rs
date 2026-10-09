//! The requirements of `docs/requirements.md` against the tree: every test
//! they name exists, every requirement names what proves it, and every
//! feature of the README has its requirement. A test renamed or deleted
//! without the document, or a feature added without a requirement, fails
//! here rather than leaving the contract quietly out of date.

use std::fs;
use std::path::{Path, PathBuf};

/// The repository root: two levels above this crate.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root exists")
}

/// The text of a file at `path` from the repository root.
fn read(path: &str) -> String {
    let file = repository_root().join(path);
    fs::read_to_string(&file).unwrap_or_else(|error| panic!("reading {}: {error}", file.display()))
}

/// The text of `docs/requirements.md`.
fn requirements() -> String {
    read("docs/requirements.md")
}

/// Every backticked token of `text` that names a test as
/// `<path>.rs::<function>`, split into the path and the function name.
fn test_references(text: &str) -> Vec<(String, String)> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|token| token.contains(".rs::"))
        .filter_map(|token| token.split_once("::"))
        .map(|(path, name)| (path.to_owned(), name.to_owned()))
        .collect()
}

/// The `## R<n>.` sections of `text`, each as its heading and its body.
fn sections(text: &str) -> Vec<(&str, &str)> {
    text.split("\n## ")
        .skip(1)
        .filter(|section| section.starts_with('R'))
        .map(|section| section.split_once('\n').unwrap_or((section, "")))
        .collect()
}

/// The title of a section heading `R<n>. <title>`.
fn title(heading: &str) -> &str {
    heading
        .split_once(". ")
        .map_or(heading, |(_, title)| title)
        .trim()
}

/// The bold titles of the bullets of the README's `## Features` section,
/// in order.
fn readme_features() -> Vec<String> {
    let readme = read("README.md");
    let features = readme
        .split_once("\n## Features\n")
        .expect("the README has a Features section")
        .1;
    let features = features.split_once("\n## ").map_or(features, |(it, _)| it);
    features
        .lines()
        .filter_map(|line| line.strip_prefix("- **"))
        .filter_map(|line| line.split_once("**"))
        .map(|(title, _)| title.to_owned())
        .collect()
}

#[test]
fn every_test_the_requirements_name_exists() {
    let root = repository_root();
    let missing: Vec<String> = test_references(&requirements())
        .into_iter()
        .filter(|(path, name)| {
            let source = fs::read_to_string(root.join(path)).unwrap_or_default();
            !source.contains(&format!("fn {name}("))
        })
        .map(|(path, name)| format!("{path}::{name}"))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/requirements.md names tests that do not exist:\n{}",
        missing.join("\n")
    );
}

#[test]
fn every_requirement_names_what_proves_it() {
    let text = requirements();
    let unproven: Vec<&str> = sections(&text)
        .into_iter()
        .filter(|(_, body)| {
            !body.contains(".rs::")
                && !body.contains("hack/loadtest.sh")
                && !body.contains(".github/workflows/")
        })
        .map(|(heading, _)| heading)
        .collect();
    assert!(
        unproven.is_empty(),
        "requirements that name nothing that proves them:\n{}",
        unproven.join("\n")
    );
}

#[test]
fn requirements_cover_every_feature_of_the_readme() {
    let features = readme_features();
    let text = requirements();
    let covered: Vec<String> = sections(&text)
        .into_iter()
        .take(features.len())
        .map(|(heading, _)| title(heading).to_owned())
        .collect();
    assert_eq!(
        covered, features,
        "the first requirements of docs/requirements.md must be the features of the README, in order"
    );
}
