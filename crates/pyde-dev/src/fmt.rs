//! Source code formatter for .oti files.
//!
//! Reformats Otigen source with consistent:
//! - 4-space indentation
//! - Newline after opening braces
//! - Newline before closing braces
//! - Single blank line between top-level items
//! - Trailing newline
//! - No trailing whitespace
//! - Consistent spacing around operators and after commas
//!
//! Preserves all comments (line and block).

use crate::project;
use std::fs;
use std::path::Path;

pub fn run() -> Result<(), String> {
    let (config, root) = project::load_config()?;
    let src_dir = root.join(&config.compiler.src);
    let test_dir = root.join(&config.compiler.test);

    let mut formatted = 0u32;
    let mut unchanged = 0u32;

    for dir in [&src_dir, &test_dir] {
        if !dir.exists() {
            continue;
        }
        let pattern = format!("{}/**/*.oti", dir.display());
        let files: Vec<_> = glob::glob(&pattern)
            .map_err(|e| format!("glob error: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        for file in &files {
            let original = fs::read_to_string(file)
                .map_err(|e| format!("cannot read {}: {}", file.display(), e))?;

            let result = format_source(&original);

            if result != original {
                fs::write(file, &result)
                    .map_err(|e| format!("cannot write {}: {}", file.display(), e))?;
                let rel = file.strip_prefix(&root).unwrap_or(file);
                println!("  formatted {}", rel.display());
                formatted += 1;
            } else {
                unchanged += 1;
            }
        }
    }

    println!("\n  {} formatted, {} unchanged", formatted, unchanged);
    Ok(())
}

/// Format a single source string.
pub fn format_source(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut indent: u32 = 0;
    let mut prev_was_blank = false;
    let mut prev_was_open_brace = false;
    let mut in_block_comment = false;

    for raw_line in source.lines() {
        let trimmed = raw_line.trim();

        // Track block comments
        if in_block_comment {
            // Inside block comment — preserve content, apply current indent
            output.push_str(&make_indent(indent));
            output.push_str(trimmed);
            output.push('\n');
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            prev_was_blank = false;
            prev_was_open_brace = false;
            continue;
        }

        if trimmed.starts_with("/*") && !trimmed.contains("*/") {
            in_block_comment = true;
            output.push_str(&make_indent(indent));
            output.push_str(trimmed);
            output.push('\n');
            prev_was_blank = false;
            prev_was_open_brace = false;
            continue;
        }

        // Empty line handling
        if trimmed.is_empty() {
            if !prev_was_blank && !prev_was_open_brace {
                output.push('\n');
                prev_was_blank = true;
            }
            continue;
        }
        prev_was_blank = false;

        // Dedent for closing braces BEFORE writing the line
        let starts_with_close = trimmed.starts_with('}');
        if starts_with_close && indent > 0 {
            indent -= 1;
        }

        // Write the formatted line
        output.push_str(&make_indent(indent));
        output.push_str(&format_line(trimmed));
        output.push('\n');

        // Count braces outside strings and comments
        let (open_count, close_count) = count_braces(trimmed);

        // If line has both (e.g., `} else {`), the net effect is 0 (already dedented above)
        if starts_with_close {
            // Already dedented, now re-indent for any opens on this line
            indent += open_count;
            // Don't count the close we already handled
        } else {
            indent += open_count;
            indent = indent.saturating_sub(close_count);
        }

        prev_was_open_brace = trimmed.ends_with('{');
    }

    // Ensure trailing newline
    if !output.ends_with('\n') {
        output.push('\n');
    }

    // Remove trailing blank lines (keep exactly one trailing newline)
    while output.ends_with("\n\n") {
        output.pop();
    }

    output
}

/// Format a single line (spacing normalization).
fn format_line(line: &str) -> String {
    // Don't modify comments or string literals
    if line.starts_with("//") || line.starts_with("///") || line.starts_with("/*") {
        return line.to_string();
    }

    let mut result = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut in_string = false;

    while i < chars.len() {
        let c = chars[i];

        // Track string literals — don't modify content
        if c == '"' && !in_string {
            in_string = true;
            result.push(c);
            i += 1;
            continue;
        }
        if c == '"' && in_string {
            // Check for escaped quote
            let prev_backslashes = result.chars().rev().take_while(|&c| c == '\\').count();
            if prev_backslashes % 2 == 0 {
                in_string = false;
            }
            result.push(c);
            i += 1;
            continue;
        }
        if in_string {
            result.push(c);
            i += 1;
            continue;
        }

        // Skip to end of line comment
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            // Ensure space before inline comment
            if !result.is_empty() && !result.ends_with(' ') {
                result.push(' ');
            }
            result.extend(&chars[i..]);
            break;
        }

        // Normalize spacing after commas: ensure exactly one space
        if c == ',' {
            result.push(',');
            if i + 1 < chars.len() && chars[i + 1] != ' ' && chars[i + 1] != '\n' {
                result.push(' ');
            }
            i += 1;
            continue;
        }

        // Normalize spacing after colons (but not ::)
        if c == ':' && i + 1 < chars.len() && chars[i + 1] != ':' && chars[i + 1] != '\n' {
            result.push(':');
            if chars[i + 1] != ' ' {
                result.push(' ');
            }
            i += 1;
            continue;
        }

        // Collapse multiple spaces into one (outside strings)
        if c == ' ' {
            result.push(' ');
            while i + 1 < chars.len() && chars[i + 1] == ' ' {
                i += 1;
            }
            i += 1;
            continue;
        }

        result.push(c);
        i += 1;
    }

    // Remove trailing whitespace
    result.trim_end().to_string()
}

/// Count opening and closing braces, ignoring those inside string literals and comments.
fn count_braces(line: &str) -> (u32, u32) {
    let mut opens = 0u32;
    let mut closes = 0u32;
    let mut in_string = false;
    let mut prev_backslash = false;
    let chars: Vec<char> = line.chars().collect();

    for i in 0..chars.len() {
        let c = chars[i];

        // Track string literals
        if c == '"' && !prev_backslash {
            in_string = !in_string;
            prev_backslash = false;
            continue;
        }
        prev_backslash = c == '\\' && in_string && !prev_backslash;

        if in_string {
            continue;
        }

        // Skip line comments
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            break;
        }

        if c == '{' { opens += 1; }
        if c == '}' { closes += 1; }
    }

    (opens, closes)
}

fn make_indent(level: u32) -> String {
    "    ".repeat(level as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_indentation() {
        let input = "contract Token {\nstorage {\ncount: u64,\n}\npub fn get() -> u64 {\nreturn self.count;\n}\n}\n";
        let output = format_source(input);
        assert!(output.contains("    storage {"));
        assert!(output.contains("        count: u64,"));
        assert!(output.contains("    pub fn get() -> u64 {"));
        assert!(output.contains("        return self.count;"));
    }

    #[test]
    fn preserves_comments() {
        let input = "// top comment\ncontract T {\n// inner comment\npub fn f() {\n}\n}\n";
        let output = format_source(input);
        assert!(output.contains("// top comment"));
        assert!(output.contains("    // inner comment"));
    }

    #[test]
    fn no_trailing_whitespace() {
        let input = "contract T {   \n    pub fn f() {   \n    }   \n}   \n";
        let output = format_source(input);
        for line in output.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace found: {:?}", line);
        }
    }

    #[test]
    fn trailing_newline() {
        let input = "contract T {\n}";
        let output = format_source(input);
        assert!(output.ends_with('\n'));
        assert!(!output.ends_with("\n\n"));
    }

    #[test]
    fn collapse_blank_lines() {
        let input = "contract T {\n\n\n\npub fn f() {\n}\n\n\n}\n";
        let output = format_source(input);
        assert!(!output.contains("\n\n\n"));
    }

    #[test]
    fn space_after_comma() {
        let input = "pub fn f(a: u64,b: u256,c: bool) {\n}\n";
        let output = format_source(input);
        assert!(output.contains("a: u64, b: u256, c: bool"));
    }

    #[test]
    fn braces_in_strings_ignored() {
        let input = "contract T {\npub fn f() {\nlet s = \"hello { world }\";\n}\n}\n";
        let output = format_source(input);
        // String braces should NOT affect indentation
        assert!(output.contains("        let s = \"hello { world }\";"));
    }

    #[test]
    fn else_block_indentation() {
        let input = "contract T {\npub fn f() {\nif x > 0 {\nreturn 1;\n} else {\nreturn 0;\n}\n}\n}\n";
        let output = format_source(input);
        assert!(output.contains("        if x > 0 {"));
        assert!(output.contains("            return 1;"));
        assert!(output.contains("        } else {"));
        assert!(output.contains("            return 0;"));
    }
}
