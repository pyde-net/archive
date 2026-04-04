use crate::project::{self, Dependency};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command as Cmd;

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

/// Install a single package (+ transitive deps), or restore all from lock file.
pub fn run(url: &str, rev: Option<&str>, name_override: Option<&str>) -> Result<(), String> {
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
    if lib_dir.join(&pkg_name).exists() {
        return Err(format!(
            "'{}' is already installed. Remove it first with `pyde-dev remove {}`",
            pkg_name, pkg_name,
        ));
    }

    fs::create_dir_all(&lib_dir)
        .map_err(|e| format!("cannot create lib/: {}", e))?;

    let mut installed: HashSet<String> = HashSet::new();
    let mut versions: HashMap<String, (String, String)> = HashMap::new();

    install_package(&root, &pkg_name, url, rev, &mut installed, &mut versions)?;

    // Update pyde.toml with the DIRECT dependency only
    let dep = Dependency {
        git: url.to_string(),
        rev: rev.map(|s| s.to_string()),
    };
    update_toml(&root, &pkg_name, &dep)?;

    let total = installed.len();
    if total > 1 {
        println!("  Installed {} + {} transitive dependencies", pkg_name, total - 1);
    }

    Ok(())
}

/// Core install logic — recursive, handles transitive deps.
fn install_package(
    root: &Path,
    pkg_name: &str,
    url: &str,
    rev: Option<&str>,
    installed: &mut HashSet<String>,
    versions: &mut HashMap<String, (String, String)>,
) -> Result<(), String> {
    if installed.contains(pkg_name) {
        return Ok(());
    }

    let lib_dir = root.join("lib");
    let pkg_dir = lib_dir.join(pkg_name);

    // Already on disk — skip clone but still check transitive deps
    if pkg_dir.exists() {
        installed.insert(pkg_name.to_string());
        resolve_transitive_deps(root, pkg_name, installed, versions)?;
        return Ok(());
    }

    fs::create_dir_all(&lib_dir)
        .map_err(|e| format!("cannot create lib/: {}", e))?;

    println!("  Installing {} from {}", pkg_name, url);

    clone_repo(url, rev, &pkg_dir)?;

    let pinned_rev = get_head_commit(&pkg_dir)
        .unwrap_or_else(|| rev.unwrap_or("main").to_string());

    // Conflict detection
    if let Some((existing_git, existing_rev)) = versions.get(pkg_name) {
        if existing_rev != &pinned_rev {
            let _ = fs::remove_dir_all(&pkg_dir);
            return Err(format!(
                "dependency conflict: '{}' required at rev {} and rev {}",
                pkg_name,
                &pinned_rev[..7.min(pinned_rev.len())],
                &existing_rev[..7.min(existing_rev.len())],
            ));
        }
    }

    let git_dir = pkg_dir.join(".git");
    if git_dir.exists() {
        let _ = fs::remove_dir_all(&git_dir);
    }

    if !pkg_dir.join("src").exists() && !has_oti_files(&pkg_dir) {
        let _ = fs::remove_dir_all(&pkg_dir);
        return Err(format!(
            "'{}' has no src/ directory or .oti files — not a valid Pyde package",
            pkg_name
        ));
    }

    update_lock(root, pkg_name, url, &pinned_rev)?;
    installed.insert(pkg_name.to_string());
    versions.insert(pkg_name.to_string(), (url.to_string(), pinned_rev.clone()));

    let oti_count = count_oti_files(&pkg_dir);
    println!("  Installed {} ({} .oti files, pinned at {})",
        pkg_name, oti_count, &pinned_rev[..7.min(pinned_rev.len())]);

    resolve_transitive_deps(root, pkg_name, installed, versions)?;

    Ok(())
}

/// Read a package's pyde.toml and install its dependencies recursively.
fn resolve_transitive_deps(
    root: &Path,
    pkg_name: &str,
    installed: &mut HashSet<String>,
    versions: &mut HashMap<String, (String, String)>,
) -> Result<(), String> {
    let pkg_toml = root.join("lib").join(pkg_name).join("pyde.toml");
    if let Some(config) = project::load_config_from(&pkg_toml)? {
        for (dep_name, dep) in &config.dependencies {
            install_package(root, dep_name, &dep.git, dep.rev.as_deref(), installed, versions)?;
        }
    }
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

    let mut count = 0;
    for pkg in &lock.packages {
        let pkg_dir = lib_dir.join(&pkg.name);
        if pkg_dir.exists() {
            continue;
        }
        println!("  Installing {} from {} (rev {})",
            pkg.name, pkg.git, &pkg.rev[..7.min(pkg.rev.len())]);
        clone_repo(&pkg.git, Some(&pkg.rev), &pkg_dir)?;
        let git_dir = pkg_dir.join(".git");
        if git_dir.exists() {
            let _ = fs::remove_dir_all(&git_dir);
        }
        count += 1;
    }

    println!("  Restored {} packages from pyde.lock", count);
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
    let ok = Cmd::new("git")
        .args(["clone", "--depth", "1", "--branch", branch, url, &dest.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("failed to run git: {}", e))?
        .success();

    if !ok {
        let ok2 = Cmd::new("git")
            .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("failed to run git: {}", e))?
            .success();
        if !ok2 {
            return Err(format!("git clone failed for {}", url));
        }
        if let Some(r) = rev {
            let ok3 = Cmd::new("git")
                .args(["-C", &dest.to_string_lossy(), "checkout", r])
                .status()
                .map_err(|e| format!("git checkout failed: {}", e))?
                .success();
            if !ok3 {
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
    let path = root.join("pyde.lock");
    fs::read_to_string(&path).ok()
        .and_then(|c| toml::from_str(&c).ok())
        .unwrap_or_default()
}

fn save_lock(root: &Path, lock: &LockFile) -> Result<(), String> {
    let content = toml::to_string_pretty(lock)
        .map_err(|e| format!("cannot serialize lock file: {}", e))?;
    fs::write(root.join("pyde.lock"), content)
        .map_err(|e| format!("cannot write pyde.lock: {}", e))
}

fn update_lock(root: &Path, name: &str, git: &str, rev: &str) -> Result<(), String> {
    let mut lock = load_lock(root);
    lock.packages.retain(|p| p.name != name);
    lock.packages.push(LockedPackage {
        name: name.to_string(), git: git.to_string(), rev: rev.to_string(),
    });
    save_lock(root, &lock)
}

fn remove_from_lock(root: &Path, name: &str) -> Result<(), String> {
    let mut lock = load_lock(root);
    lock.packages.retain(|p| p.name != name);
    save_lock(root, &lock)
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
            let insert_at = rest.find("\n[").map(|i| after + i).unwrap_or(content.len());
            format!("{}{}\n{}", &content[..insert_at], dep_line, &content[insert_at..])
        } else { content }
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
    let new_content: String = content.lines()
        .filter(|l| !l.starts_with(&prefix))
        .collect::<Vec<_>>().join("\n");
    fs::write(&toml_path, format!("{}\n", new_content.trim_end()))
        .map_err(|e| format!("cannot write pyde.toml: {}", e))
}

fn format_dep_line(name: &str, dep: &Dependency) -> String {
    match &dep.rev {
        Some(rev) => format!("{} = {{ git = \"{}\", rev = \"{}\" }}", name, dep.git, rev),
        None => format!("{} = {{ git = \"{}\" }}", name, dep.git),
    }
}

fn parse_repo_name(url: &str) -> String {
    url.trim_end_matches('/').rsplit('/').next().unwrap_or("").trim_end_matches(".git").to_string()
}

fn has_oti_files(dir: &Path) -> bool {
    fs::read_dir(dir).ok().map(|entries| {
        entries.flatten().any(|e| {
            let p = e.path();
            (p.is_file() && p.extension().map(|x| x == "oti").unwrap_or(false))
                || (p.is_dir() && has_oti_files(&p))
        })
    }).unwrap_or(false)
}

fn count_oti_files(dir: &Path) -> usize {
    fs::read_dir(dir).ok().map(|entries| {
        entries.flatten().map(|e| {
            let p = e.path();
            if p.is_file() && p.extension().map(|x| x == "oti").unwrap_or(false) { 1 }
            else if p.is_dir() { count_oti_files(&p) }
            else { 0 }
        }).sum()
    }).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_name_https() {
        assert_eq!(parse_repo_name("https://github.com/user/my-lib.git"), "my-lib");
    }

    #[test]
    fn parse_repo_name_no_suffix() {
        assert_eq!(parse_repo_name("https://github.com/user/my-lib"), "my-lib");
    }

    #[test]
    fn parse_repo_name_trailing_slash() {
        assert_eq!(parse_repo_name("https://github.com/user/my-lib/"), "my-lib");
    }

    #[test]
    fn format_dep_with_rev() {
        let dep = Dependency { git: "https://x.com/lib.git".into(), rev: Some("v1".into()) };
        assert!(format_dep_line("lib", &dep).contains("rev = \"v1\""));
    }

    #[test]
    fn format_dep_no_rev() {
        let dep = Dependency { git: "https://x.com/lib.git".into(), rev: None };
        assert!(!format_dep_line("lib", &dep).contains("rev"));
    }

    #[test]
    fn lock_roundtrip() {
        let lock = LockFile {
            packages: vec![
                LockedPackage { name: "a".into(), git: "u1".into(), rev: "r1".into() },
                LockedPackage { name: "b".into(), git: "u2".into(), rev: "r2".into() },
            ],
        };
        let s = toml::to_string_pretty(&lock).unwrap();
        let p: LockFile = toml::from_str(&s).unwrap();
        assert_eq!(p.packages.len(), 2);
    }
}
