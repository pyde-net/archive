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

    // Write standard library
    fs::create_dir_all(root.join("lib/@std"))
        .map_err(|e| format!("cannot create lib/@std/: {}", e))?;
    fs::write(root.join("lib/@std/vm.oti"), STD_VM)
        .map_err(|e| format!("cannot write vm.oti: {}", e))?;
    fs::write(root.join("lib/@std/token.oti"), STD_TOKEN)
        .map_err(|e| format!("cannot write token.oti: {}", e))?;
    fs::write(root.join("lib/@std/math.oti"), STD_MATH)
        .map_err(|e| format!("cannot write math.oti: {}", e))?;

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
    println!("      └── @std/");
    println!("          ├── vm.oti");
    println!("          ├── token.oti");
    println!("          └── math.oti");
    println!();
    println!("  Get started:");
    println!("    cd {}", name);
    println!("    pyde-dev build");
    println!("    pyde-dev test");

    Ok(())
}

// Standard library files (embedded at compile time from stdlib/)
const STD_VM: &str = include_str!("../stdlib/vm.oti");
const STD_TOKEN: &str = include_str!("../stdlib/token.oti");
const STD_MATH: &str = include_str!("../stdlib/math.oti");

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

const STARTER_TEST: &str = r#"use counter::Counter;

contract CounterTest {
    #[test]
    fn test_deploy() {
        let c = deploy!(Counter);
        assert!(c.get_count() == 0);
    }

    #[test]
    fn test_increment() {
        let c = deploy!(Counter);
        c.increment();
        assert!(c.get_count() == 1);
    }

    #[test]
    fn test_add() {
        let c = deploy!(Counter);
        c.add(5);
        assert!(c.get_count() == 5);
    }
}
"#;
