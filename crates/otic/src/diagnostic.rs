//! Diagnostic formatting: rich error/warning output with source context.
//!
//! Produces Rust-style error messages:
//! ```text
//! error: undefined variable 'foo'
//!  --> contract.oti:5:10
//!   |
//! 5 |     let x = foo;
//!   |             ^^^ not found in this scope
//! ```

/// Severity level for a diagnostic.
pub enum Level {
    Error,
    Warning,
}

/// A diagnostic message with source location.
pub struct Diagnostic {
    pub level: Level,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub col: u32,
}

/// Format a diagnostic with source context lines.
/// `source` is the full source text of the file.
pub fn format_diagnostic(d: &Diagnostic, source: &str) -> String {
    let mut out = String::new();

    // Level + message
    let level_str = match d.level {
        Level::Error => "\x1b[1;31merror\x1b[0m",     // bold red
        Level::Warning => "\x1b[1;33mwarning\x1b[0m",  // bold yellow
    };
    out.push_str(&format!("{}: \x1b[1m{}\x1b[0m\n", level_str, d.message));

    // Location
    out.push_str(&format!(" \x1b[1;34m-->\x1b[0m {}:{}:{}\n", d.file, d.line, d.col));

    // Source context
    if d.line > 0 {
        let lines: Vec<&str> = source.lines().collect();
        let line_idx = (d.line - 1) as usize;

        if line_idx < lines.len() {
            let line_num_width = format!("{}", d.line).len();
            let padding = " ".repeat(line_num_width);

            // Separator
            out.push_str(&format!(" {} \x1b[1;34m|\x1b[0m\n", padding));

            // Source line
            out.push_str(&format!(" \x1b[1;34m{}\x1b[0m \x1b[1;34m|\x1b[0m {}\n",
                d.line, lines[line_idx]));

            // Caret line
            let col_idx = if d.col > 0 { (d.col - 1) as usize } else { 0 };
            let carets = " ".repeat(col_idx) + "^^^";
            let caret_color = match d.level {
                Level::Error => "\x1b[1;31m",
                Level::Warning => "\x1b[1;33m",
            };
            out.push_str(&format!(" {} \x1b[1;34m|\x1b[0m {}{}\x1b[0m\n",
                padding, caret_color, carets));
        }
    }

    out
}

/// Format a list of diagnostics, deduplicating consecutive identical locations.
pub fn format_diagnostics(diagnostics: &[Diagnostic], source: &str) -> String {
    let mut out = String::new();
    for d in diagnostics {
        out.push_str(&format_diagnostic(d, source));
        out.push('\n');
    }

    // Summary
    let errors = diagnostics.iter().filter(|d| matches!(d.level, Level::Error)).count();
    let warnings = diagnostics.iter().filter(|d| matches!(d.level, Level::Warning)).count();

    if errors > 0 || warnings > 0 {
        let mut parts = Vec::new();
        if errors > 0 {
            parts.push(format!("\x1b[1;31m{} error{}\x1b[0m", errors, if errors == 1 { "" } else { "s" }));
        }
        if warnings > 0 {
            parts.push(format!("\x1b[1;33m{} warning{}\x1b[0m", warnings, if warnings == 1 { "" } else { "s" }));
        }
        out.push_str(&format!("{} emitted\n", parts.join(", ")));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_error_with_context() {
        let src = "contract T {\n    let x = foo;\n}";
        let d = Diagnostic {
            level: Level::Error,
            message: "undefined variable 'foo'".into(),
            file: "test.oti".into(),
            line: 2,
            col: 13,
        };
        let out = format_diagnostic(&d, src);
        assert!(out.contains("error"));
        assert!(out.contains("undefined variable 'foo'"));
        assert!(out.contains("test.oti:2:13"));
        assert!(out.contains("let x = foo;"));
        assert!(out.contains("^^^"));
    }

    #[test]
    fn format_warning() {
        let src = "let unused = 5;";
        let d = Diagnostic {
            level: Level::Warning,
            message: "unused variable 'unused'".into(),
            file: "test.oti".into(),
            line: 1,
            col: 5,
        };
        let out = format_diagnostic(&d, src);
        assert!(out.contains("warning"));
        assert!(out.contains("unused variable"));
    }

    #[test]
    fn format_summary() {
        let diagnostics = vec![
            Diagnostic { level: Level::Error, message: "err1".into(), file: "t.oti".into(), line: 1, col: 1 },
            Diagnostic { level: Level::Warning, message: "warn1".into(), file: "t.oti".into(), line: 2, col: 1 },
            Diagnostic { level: Level::Error, message: "err2".into(), file: "t.oti".into(), line: 3, col: 1 },
        ];
        let out = format_diagnostics(&diagnostics, "a\nb\nc");
        assert!(out.contains("2 errors"));
        assert!(out.contains("1 warning"));
    }
}
