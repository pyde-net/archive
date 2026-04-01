use crate::project;
use std::fs;
use std::path::Path;

pub fn run(name: &str) -> Result<(), String> {
    let root = Path::new(name);
    if root.exists() {
        return Err(format!("directory '{}' already exists", name));
    }

    // Create project structure
    fs::create_dir_all(root.join("src"))
        .map_err(|e| format!("cannot create src/: {}", e))?;
    fs::create_dir_all(root.join("test"))
        .map_err(|e| format!("cannot create test/: {}", e))?;
    fs::create_dir_all(root.join("script"))
        .map_err(|e| format!("cannot create script/: {}", e))?;
    fs::create_dir_all(root.join("lib"))
        .map_err(|e| format!("cannot create lib/: {}", e))?;

    // Write pyde.toml
    fs::write(root.join("pyde.toml"), project::default_toml(name))
        .map_err(|e| format!("cannot write pyde.toml: {}", e))?;

    // Write starter contract
    fs::write(root.join("src/Counter.oti"), STARTER_CONTRACT)
        .map_err(|e| format!("cannot write Counter.oti: {}", e))?;

    // Write starter test
    fs::write(root.join("test/Counter.test.oti"), STARTER_TEST)
        .map_err(|e| format!("cannot write Counter.test.oti: {}", e))?;

    // Write .gitignore
    fs::write(root.join(".gitignore"), "out/\n")
        .map_err(|e| format!("cannot write .gitignore: {}", e))?;

    println!("  Initialized project '{}'", name);
    println!();
    println!("  {}/", name);
    println!("  ├── pyde.toml");
    println!("  ├── src/");
    println!("  │   └── Counter.oti");
    println!("  ├── test/");
    println!("  │   └── Counter.test.oti");
    println!("  ├── script/");
    println!("  └── lib/");
    println!();
    println!("  Get started:");
    println!("    cd {}", name);
    println!("    pyde-dev build");
    println!("    pyde-dev test");

    Ok(())
}

const STARTER_CONTRACT: &str = r#"contract Counter {
    storage {
        count: u64,
    }

    #[constructor]
    pub fn init() {
        self.count = 0;
    }

    pub fn get_count() -> u64 {
        return self.count;
    }

    pub fn increment() {
        self.count = self.count + 1;
    }

    pub fn add(value: u64) {
        self.count = self.count + value;
    }
}
"#;

const STARTER_TEST: &str = r#"contract Counter {
    storage {
        count: u64,
    }

    #[constructor]
    pub fn init() {
        self.count = 0;
    }

    pub fn get_count() -> u64 {
        return self.count;
    }

    pub fn increment() {
        self.count = self.count + 1;
    }

    pub fn add(value: u64) {
        self.count = self.count + value;
    }

    #[test]
    fn test_initial_count() {
        assert!(self.count == 0);
    }

    #[test]
    fn test_increment() {
        self.count = self.count + 1;
        assert!(self.count == 1);
    }

    #[test]
    fn test_add_five() {
        self.count = self.count + 5;
        assert!(self.count == 5);
    }
}
"#;
