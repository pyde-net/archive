use crate::project;
use std::fs;

pub fn run() -> Result<(), String> {
    let (config, root) = project::load_config()?;
    let out_dir = root.join(&config.compiler.out);

    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)
            .map_err(|e| format!("cannot remove {}: {}", out_dir.display(), e))?;
        println!("  removed {}", out_dir.display());
    } else {
        println!("  nothing to clean");
    }

    Ok(())
}
