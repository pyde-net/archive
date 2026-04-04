use crate::project::{self, Dependency};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command as Cmd;

/// Locked package entry (exact commit pinned).
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
struct LockedPackage {
    name: String,
    git: String,
    rev: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
struct LockFile {
    #[serde(default, rename = "package")]
    packages: Vec<LockedPackage>,
}

/// Install a single package from a git URL, or restore all from lock file.
pub fn run(url: &str, rev: Option<&str>, name_override: Option<&str>) -> Result<(), String> {
    // `pyde install` (no url) → restore all deps from lock file
    if url == "__restore__" {
        return restore_all();
    }

    let (_, root) = project::load_config()?;
    let pkg_name = name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| parse_repo_name(url));

    if pkg_name.is_empty() {
        return Err("cannot determine package name from URL — use --name".into());
    }

    let lib_dir = root.join("lib");
    let pkg_dir = lib_dir.join(&pkg_name);

    if pkg_dir.exists() {
        return Err(format!(
            "'{}' is already installed. Remove it first with `pyde-dev remove {}`",
            pkg_name, pkg_name,
        ));
    }

    fs::create_dir_all(&lib_dir)
        .map_err(|e| format!("cannot create lib/: {}", e))?;

    println!("  Installing {} from {}", pkg_name, url);

    // Clone
    clone_repo(url, rev, &pkg_dir)?;

    // Capture exact commit hash BEFORE removing .git/
    let pinned_rev = get_head_commit(&pkg_dir).unwrap_or_else(|| {
        rev.unwrap_or("main").to_string()
    });

    // Remove .git/ (no nested repos)
    let git_dir = pkg_dir.join(".git");
    if git_dir.exists() {
        let _ = fs::remove_dir_all(&git_dir);
    }

    // Verify
    if !pkg_dir.join("src").exists() && !has_oti_files(&pkg_dir) {
        let _ = fs::remove_dir_all(&pkg_dir);
        return Err(format!(
            "'{}' has no src/ directory or .oti files — not a valid Pyde package",
            pkg_name
        ));
    }

    // Update pyde.toml
    let dep = Dependency {
        git: url.to_string(),
        rev: rev.map(|s| s.to_string()),
    };
    update_toml(&root, &pkg_name, &dep)?;

    // Update pyde.lock
    update_lock(&root, &pkg_name, url, &pinned_rev)?;

    let oti_count = count_oti_files(&pkg_dir);
    println!("  Installed {} ({} .oti files, pinned at {})", pkg_name, oti_count, &pinned_rev[..7.min(pinned_rev.len())]);

    Ok(())
}

/// Restore all dependencies from pyde.lock.
fn restore_all() -> Result<(), String> {
    let (_, root) = project::load_config()?;
    let lock = load_lock(&root);

    if lock.packages.is_empty() {
        println!("  No dependencies to install (pyde.lock is empty)");
        return Ok(());
    }

    let lib_dir = root.join("lib");
    fs::create_dir_all(&lib_dir)
        .map_err(|e| format!("cannot create lib/: {}", e))?;

    for pkg in &lock.packages {
        let pkg_dir = lib_dir.join(&pkg.name);
        if pkg_dir.exists() {
            println!("  {} — already installed, skipping", pkg.name);
            continue;
        }

        println!("  Installing {} from {} (rev {})", pkg.name, pkg.git, &pkg.rev[..7.min(pkg.rev.len())]);
        clone_repo(&pkg.git, Some(&pkg.rev), &pkg_dir)?;

        let git_dir = pkg_dir.join(".git");
        if git_dir.exists() {
            let _ = fs::remove_dir_all(&git_dir);
        }
    }

    println!("  Restored {} packages from pyde.lock", lock.packages.len());
    Ok(())
}

/// Remove an installed package.
pub fn remove(name: &str) -> Result<(), String> {
    let (_, root) = project::load_config()?;
    let pkg_dir = root.join("lib").join(name);

    if !pkg_dir.exists() {
        return Err(format!("package '{}' is not installed", name));
    }
    if name.starts_with('@') {
        return Err(format!("cannot remove built-in package '{}'", name));
    }

    fs::remove_dir_all(&pkg_dir)
        .map_err(|e| format!("cannot remove {}: {}", pkg_dir.display(), e))?;

    remove_from_toml(&root, name)?;
    remove_from_lock(&root, name)?;

    println!("  Removed {}", name);
    Ok(())
}

// ============================================================================
// Git helpers
// ============================================================================

fn clone_repo(url: &str, rev: Option<&str>, dest: &Path) -> Result<(), String> {
    let branch = rev.unwrap_or("main");
    let status = Cmd::new("git")
        .args(["clone", "--depth", "1", "--branch", branch, url, &dest.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("failed to run git: {}", e))?;

    if !status.success() {
        // Retry without --branch (commit hash or default branch differs)
        let status2 = Cmd::new("git")
            .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("failed to run git: {}", e))?;

        if !status2.success() {
            return Err(format!("git clone failed for {}", url));
        }

        if let Some(r) = rev {
            let checkout = Cmd::new("git")
                .args(["-C", &dest.to_string_lossy(), "checkout", r])
                .status()
                .map_err(|e| format!("git checkout failed: {}", e))?;
            if !checkout.success() {
                let _ = fs::remove_dir_all(dest);
                return Err(format!("git checkout '{}' failed", r));
            }
        }
    }

    Ok(())
}

fn get_head_commit(repo_dir: &Path) -> Option<String> {
    let output = Cmd::new("git")
        .args(["-C", &repo_dir.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

// ============================================================================
// Lock file
// ============================================================================

fn load_lock(root: &Path) -> LockFile {
    let lock_path = root.join("pyde.lock");
    if let Ok(content) = fs::read_to_string(&lock_path) {
        toml::from_str(&content).unwrap_or_default()
    } else {
        LockFile::default()
    }
}

fn save_lock(root: &Path, lock: &LockFile) -> Result<(), String> {
    let content = toml::to_string_pretty(lock)
        .map_err(|e| format!("cannot serialize lock file: {}", e))?;
    fs::write(root.join("pyde.lock"), content)
        .map_err(|e| format!("cannot write pyde.lock: {}", e))
}

fn update_lock(root: &Path, name: &str, git: &str, rev: &str) -> Result<(), String> {
    let mut lock = load_lock(root);
    // Remove existing entry if present
    lock.packages.retain(|p| p.name != name);
    lock.packages.push(LockedPackage {
        name: name.to_string(),
        git: git.to_string(),
        rev: rev.to_string(),
    });
    save_lock(root, &lock)
}

fn remove_from_lock(root: &Path, name: &str) -> Result<(), String> {
    let mut lock = load_lock(root);
    lock.packages.retain(|p| p.name != name);
    save_lock(root, &lock)
}

// ============================================================================
// URL / file helpers
// ============================================================================

fn parse_repo_name(url: &str) -> String {
    let url = url.trim_end_matches('/');
    url.rsplit('/').next().unwrap_or("").trim_end_matches(".git").to_string()
}

fn has_oti_files(dir: &Path) -> bool {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "oti").unwrap_or(false) {
                return true;
            }
            if path.is_dir() && has_oti_files(&path) {
                return true;
            }
        }
    }
    false
}

fn count_oti_files(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "oti").unwrap_or(false) {
                count += 1;
            }
            if path.is_dir() {
                count += count_oti_files(&path);
            }
        }
    }
    count
}

// ============================================================================
// pyde.toml manipulation
// ============================================================================

fn update_toml(root: &Path, name: &str, dep: &Dependency) -> Result<(), String> {
    let toml_path = root.join("pyde.toml");
    let content = fs::read_to_string(&toml_path)
        .map_err(|e| format!("cannot read pyde.toml: {}", e))?;

    let dep_line = format_dep_line(name, dep);
    let new_content = if content.contains("[dependencies]") {
        if let Some(idx) = content.find("[dependencies]") {
            let after = idx + "[dependencies]".len();
            let rest = &content[after..];
            let insert_at = if let Some(next_section) = rest.find("\n[") {
                after + next_section
            } else {
                content.len()
            };
            format!("{}{}\n{}", &content[..insert_at], dep_line, &content[insert_at..])
        } else {
            content
        }
    } else {
        format!("{}\n[dependencies]\n{}\n", content.trim_end(), dep_line)
    };

    fs::write(&toml_path, new_content)
        .map_err(|e| format!("cannot write pyde.toml: {}", e))
}

fn remove_from_toml(root: &Path, name: &str) -> Result<(), String> {
    let toml_path = root.join("pyde.toml");
    let content = fs::read_to_string(&toml_path)
        .map_err(|e| format!("cannot read pyde.toml: {}", e))?;
    let prefix = format!("{} = ", name);
    let new_content: String = content
        .lines()
        .filter(|line| !line.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&toml_path, format!("{}\n", new_content.trim_end()))
        .map_err(|e| format!("cannot write pyde.toml: {}", e))
}

fn format_dep_line(name: &str, dep: &Dependency) -> String {
    if let Some(ref rev) = dep.rev {
        format!("{} = {{ git = \"{}\", rev = \"{}\" }}", name, dep.git, rev)
    } else {
        format!("{} = {{ git = \"{}\" }}", name, dep.git)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_name_https() {
        assert_eq!(parse_repo_name("https://github.com/user/my-lib.git"), "my-lib");
    }

    #[test]
    fn parse_repo_name_no_git_suffix() {
        assert_eq!(parse_repo_name("https://github.com/user/my-lib"), "my-lib");
    }

    #[test]
    fn parse_repo_name_trailing_slash() {
        assert_eq!(parse_repo_name("https://github.com/user/my-lib/"), "my-lib");
    }

    #[test]
    fn parse_repo_name_ssh() {
        assert_eq!(parse_repo_name("git@github.com:user/my-lib.git"), "my-lib");
    }

    #[test]
    fn format_dep_line_with_rev() {
        let dep = Dependency { git: "https://github.com/user/lib.git".into(), rev: Some("v1.0".into()) };
        assert_eq!(format_dep_line("mylib", &dep), "mylib = { git = \"https://github.com/user/lib.git\", rev = \"v1.0\" }");
    }

    #[test]
    fn format_dep_line_no_rev() {
        let dep = Dependency { git: "https://github.com/user/lib.git".into(), rev: None };
        assert_eq!(format_dep_line("mylib", &dep), "mylib = { git = \"https://github.com/user/lib.git\" }");
    }

    #[test]
    fn lock_file_roundtrip() {
        let lock = LockFile {
            packages: vec![
                LockedPackage { name: "foo".into(), git: "https://example.com/foo".into(), rev: "abc123".into() },
                LockedPackage { name: "bar".into(), git: "https://example.com/bar".into(), rev: "def456".into() },
            ],
        };
        let s = toml::to_string_pretty(&lock).unwrap();
        let parsed: LockFile = toml::from_str(&s).unwrap();
        assert_eq!(parsed.packages.len(), 2);
        assert_eq!(parsed.packages[0].name, "foo");
        assert_eq!(parsed.packages[1].rev, "def456");
    }
}
