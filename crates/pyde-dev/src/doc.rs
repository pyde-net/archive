//! Documentation generator: extracts contract API docs from .oti source files.
//!
//! Generates markdown files in out/docs/ with:
//! - Contract overview and storage layout
//! - Public function signatures with doc comments
//! - Events with field descriptions
//! - Errors with field descriptions
//! - Interfaces, structs, enums

use crate::project;
use std::fs;

pub fn run() -> Result<(), String> {
    let (config, root) = project::load_config()?;
    let src_dir = root.join(&config.compiler.src);
    let docs_dir = root.join(&config.compiler.out).join("docs");

    if !src_dir.exists() {
        return Err(format!(
            "source directory '{}' not found",
            src_dir.display()
        ));
    }

    fs::create_dir_all(&docs_dir).map_err(|e| format!("cannot create docs directory: {}", e))?;

    let pattern = format!("{}/**/*.oti", src_dir.display());
    let files: Vec<_> = glob::glob(&pattern)
        .map_err(|e| format!("glob error: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

    if files.is_empty() {
        return Err(format!("no .oti files found in {}", src_dir.display()));
    }

    let mut total_files = 0;

    for file in &files {
        let source = fs::read_to_string(file)
            .map_err(|e| format!("cannot read {}: {}", file.display(), e))?;
        let rel = file.strip_prefix(&root).unwrap_or(file);

        let (tokens, lex_errors) = otic::lexer::Lexer::new(&source).tokenize();
        if !lex_errors.is_empty() {
            eprintln!("  {} — lex errors, skipping", rel.display());
            continue;
        }

        let (ast, parse_errors) = otic::parser::Parser::new(tokens).parse();
        if !parse_errors.is_empty() {
            eprintln!("  {} — parse errors, skipping", rel.display());
            continue;
        }

        // Collect top-level items (outside contracts) for module-level docs
        let mut has_top_level = false;
        let mut top_level_md = String::new();
        let file_stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        for item in &ast.items {
            match item {
                otic::ast::Item::Contract(contract) => {
                    let md = generate_contract_doc(contract);
                    let doc_path = docs_dir.join(format!("{}.md", contract.name.name));
                    fs::write(&doc_path, &md)
                        .map_err(|e| format!("cannot write {}: {}", doc_path.display(), e))?;
                    println!("  {} → {}", contract.name.name, doc_path.display());
                    total_files += 1;
                }
                otic::ast::Item::Interface(iface) => {
                    let md = generate_interface_doc(iface);
                    let doc_path = docs_dir.join(format!("{}.md", iface.name.name));
                    fs::write(&doc_path, &md)
                        .map_err(|e| format!("cannot write {}: {}", doc_path.display(), e))?;
                    println!("  {} → {}", iface.name.name, doc_path.display());
                    total_files += 1;
                }
                otic::ast::Item::Function(f) if f.is_pub => {
                    if !has_top_level {
                        top_level_md.push_str(&format!("# {}\n\n", file_stem));
                        top_level_md.push_str("## Functions\n\n");
                        has_top_level = true;
                    }
                    top_level_md.push_str(&format_function_sig(f));
                    top_level_md.push('\n');
                }
                otic::ast::Item::Struct(s) => {
                    if !has_top_level {
                        top_level_md.push_str(&format!("# {}\n\n", file_stem));
                        has_top_level = true;
                    }
                    top_level_md.push_str(&format!("## struct {}\n\n", s.name.name));
                    if !s.fields.is_empty() {
                        top_level_md.push_str("| Field | Type |\n|-------|------|\n");
                        for field in &s.fields {
                            top_level_md.push_str(&format!(
                                "| `{}` | `{}` |\n",
                                field.name.name,
                                format_type(&field.ty)
                            ));
                        }
                        top_level_md.push('\n');
                    }
                }
                otic::ast::Item::Enum(e) => {
                    if !has_top_level {
                        top_level_md.push_str(&format!("# {}\n\n", file_stem));
                        has_top_level = true;
                    }
                    top_level_md.push_str(&format!("## enum {}\n\n", e.name.name));
                    for variant in &e.variants {
                        top_level_md.push_str(&format!("- `{}`\n", variant.name));
                    }
                    top_level_md.push('\n');
                }
                otic::ast::Item::Error(e) => {
                    if !has_top_level {
                        top_level_md.push_str(&format!("# {}\n\n", file_stem));
                        has_top_level = true;
                    }
                    top_level_md.push_str(&format!("## error {}\n\n", e.name.name));
                    if let Some(ref doc) = e.doc {
                        top_level_md.push_str(&format!("> {}\n\n", doc));
                    }
                    if !e.fields.is_empty() {
                        top_level_md.push_str("| Field | Type |\n|-------|------|\n");
                        for field in &e.fields {
                            top_level_md.push_str(&format!(
                                "| `{}` | `{}` |\n",
                                field.name.name,
                                format_type(&field.ty)
                            ));
                        }
                        top_level_md.push('\n');
                    }
                }
                otic::ast::Item::TypeAlias(t) => {
                    if !has_top_level {
                        top_level_md.push_str(&format!("# {}\n\n", file_stem));
                        has_top_level = true;
                    }
                    top_level_md.push_str(&format!(
                        "## type {} = `{}`\n\n",
                        t.name.name,
                        format_type(&t.ty)
                    ));
                }
                otic::ast::Item::Const(c) if c.is_pub => {
                    if !has_top_level {
                        top_level_md.push_str(&format!("# {}\n\n", file_stem));
                        has_top_level = true;
                    }
                    let ty_str = c.ty.as_ref().map(format_type).unwrap_or("unknown".into());
                    top_level_md.push_str(&format!("## const {} : `{}`\n\n", c.name.name, ty_str));
                }
                _ => {}
            }
        }

        // Write top-level module doc if it has standalone items
        if has_top_level {
            let doc_path = docs_dir.join(format!("{}.md", file_stem));
            // Append to existing file if contract already wrote it, or create new
            if doc_path.exists() {
                let existing = fs::read_to_string(&doc_path).unwrap_or_default();
                fs::write(&doc_path, format!("{}\n---\n\n{}", existing, top_level_md))
                    .map_err(|e| format!("cannot write {}: {}", doc_path.display(), e))?;
            } else {
                fs::write(&doc_path, &top_level_md)
                    .map_err(|e| format!("cannot write {}: {}", doc_path.display(), e))?;
                println!("  {} → {}", file_stem, doc_path.display());
                total_files += 1;
            }
        }
    }

    println!(
        "\n  {} doc file(s) generated in {}",
        total_files,
        docs_dir.display()
    );
    Ok(())
}

fn generate_contract_doc(contract: &otic::ast::ContractDef) -> String {
    let mut md = String::new();

    md.push_str(&format!("# {}\n\n", contract.name.name));

    // Storage
    let storage_fields: Vec<&otic::ast::StorageField> = contract
        .items
        .iter()
        .filter_map(|item| {
            if let otic::ast::ContractItem::Storage(s) = item {
                Some(s.fields.iter().collect::<Vec<_>>())
            } else {
                None
            }
        })
        .flatten()
        .collect();

    if !storage_fields.is_empty() {
        md.push_str("## Storage\n\n");
        md.push_str("| Field | Type |\n");
        md.push_str("|-------|------|\n");
        for field in &storage_fields {
            md.push_str(&format!(
                "| `{}` | `{}` |\n",
                field.name.name,
                format_type(&field.ty)
            ));
        }
        md.push('\n');
    }

    // Functions
    let functions: Vec<&otic::ast::FunctionDef> = contract
        .items
        .iter()
        .filter_map(|item| {
            if let otic::ast::ContractItem::Function(f) = item {
                Some(f)
            } else {
                None
            }
        })
        .collect();

    let pub_fns: Vec<&&otic::ast::FunctionDef> = functions
        .iter()
        .filter(|f| f.is_pub && !f.is_constructor() && !f.is_test())
        .collect();
    let constructor = functions.iter().find(|f| f.is_constructor());

    if let Some(ctor) = constructor {
        md.push_str("## Constructor\n\n");
        md.push_str(&format_function_sig(ctor));
        md.push('\n');
    }

    if !pub_fns.is_empty() {
        md.push_str("## Functions\n\n");
        for func in &pub_fns {
            md.push_str(&format_function_sig(func));
            md.push('\n');
        }
    }

    // Receive / Fallback
    let receive = functions.iter().find(|f| f.is_receive());
    let fallback = functions.iter().find(|f| f.is_fallback());
    if receive.is_some() || fallback.is_some() {
        md.push_str("## Special Functions\n\n");
        if let Some(recv) = receive {
            md.push_str("### receive\n\n");
            md.push_str("Called when the contract receives native tokens with no calldata.\n\n");
            if let Some(ref doc) = recv.doc {
                md.push_str(&format!("> {}\n\n", doc));
            }
            md.push_str("**Attributes:** `#[receive]` `#[payable]`\n\n");
        }
        if let Some(fb) = fallback {
            md.push_str("### fallback\n\n");
            md.push_str("Called when no function selector matches.\n\n");
            if let Some(ref doc) = fb.doc {
                md.push_str(&format!("> {}\n\n", doc));
            }
            let payable_tag = if fb.is_payable() { " `#[payable]`" } else { "" };
            md.push_str(&format!("**Attributes:** `#[fallback]`{}\n\n", payable_tag));
        }
    }

    // Events
    let events: Vec<&otic::ast::EventDef> = contract
        .items
        .iter()
        .filter_map(|item| {
            if let otic::ast::ContractItem::Event(e) = item {
                Some(e)
            } else {
                None
            }
        })
        .collect();

    if !events.is_empty() {
        md.push_str("## Events\n\n");
        for event in &events {
            md.push_str(&format!("### {}\n\n", event.name.name));
            if let Some(ref doc) = event.doc {
                md.push_str(&format!("> {}\n\n", doc));
            }
            if !event.fields.is_empty() {
                md.push_str("| Field | Type | Indexed |\n");
                md.push_str("|-------|------|--------|\n");
                for field in &event.fields {
                    let indexed = if field.indexed { "yes" } else { "" };
                    md.push_str(&format!(
                        "| `{}` | `{}` | {} |\n",
                        field.name.name,
                        format_type(&field.ty),
                        indexed
                    ));
                }
                md.push('\n');
            }
        }
    }

    // Errors
    let errors: Vec<&otic::ast::ErrorDef> = contract
        .items
        .iter()
        .filter_map(|item| {
            if let otic::ast::ContractItem::Error(e) = item {
                Some(e)
            } else {
                None
            }
        })
        .collect();

    if !errors.is_empty() {
        md.push_str("## Errors\n\n");
        for error in &errors {
            md.push_str(&format!("### {}\n\n", error.name.name));
            if let Some(ref doc) = error.doc {
                md.push_str(&format!("> {}\n\n", doc));
            }
            if !error.fields.is_empty() {
                md.push_str("| Field | Type |\n");
                md.push_str("|-------|------|\n");
                for field in &error.fields {
                    md.push_str(&format!(
                        "| `{}` | `{}` |\n",
                        field.name.name,
                        format_type(&field.ty)
                    ));
                }
                md.push('\n');
            }
        }
    }

    md
}

fn generate_interface_doc(iface: &otic::ast::InterfaceDef) -> String {
    let mut md = String::new();
    md.push_str(&format!("# {} (Interface)\n\n", iface.name.name));

    for func in &iface.functions {
        let params: Vec<String> = func
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name.name, format_type(&p.ty)))
            .collect();
        let ret = func
            .return_type
            .as_ref()
            .map(|t| format!(" -> {}", format_type(t)))
            .unwrap_or_default();
        md.push_str(&format!("### {}\n\n", func.name.name));
        md.push_str(&format!(
            "```\nfn {}({}){}\n```\n\n",
            func.name.name,
            params.join(", "),
            ret
        ));
    }

    md
}

fn format_function_sig(func: &otic::ast::FunctionDef) -> String {
    let mut md = String::new();
    md.push_str(&format!("### {}\n\n", func.name.name));

    if let Some(ref doc) = func.doc {
        md.push_str(&format!("> {}\n\n", doc));
    }

    let params: Vec<String> = func
        .params
        .iter()
        .map(|p| format!("{}: {}", p.name.name, format_type(&p.ty)))
        .collect();
    let ret = func
        .return_type
        .as_ref()
        .map(|t| format!(" -> {}", format_type(t)))
        .unwrap_or_default();

    let mut attrs = Vec::new();
    if func.is_view() {
        attrs.push("#[view]");
    }
    if func.is_payable() {
        attrs.push("#[payable]");
    }
    if func.is_reentrant() {
        attrs.push("#[reentrant]");
    }
    if func.is_constructor() {
        attrs.push("#[constructor]");
    }

    let attr_line = if attrs.is_empty() {
        String::new()
    } else {
        format!("{}\n", attrs.join(" "))
    };

    md.push_str(&format!(
        "```\n{}pub fn {}({}){}\n```\n",
        attr_line,
        func.name.name,
        params.join(", "),
        ret
    ));
    md
}

fn format_type(ty: &otic::ast::Type) -> String {
    match ty {
        otic::ast::Type::Primitive(p, _) => match p {
            otic::ast::PrimitiveType::U8 => "u8",
            otic::ast::PrimitiveType::U16 => "u16",
            otic::ast::PrimitiveType::U32 => "u32",
            otic::ast::PrimitiveType::U64 => "u64",
            otic::ast::PrimitiveType::U128 => "u128",
            otic::ast::PrimitiveType::U256 => "u256",
            otic::ast::PrimitiveType::I8 => "i8",
            otic::ast::PrimitiveType::I16 => "i16",
            otic::ast::PrimitiveType::I32 => "i32",
            otic::ast::PrimitiveType::I64 => "i64",
            otic::ast::PrimitiveType::I128 => "i128",
            otic::ast::PrimitiveType::I256 => "i256",
            otic::ast::PrimitiveType::Bool => "bool",
            otic::ast::PrimitiveType::Address => "Address",
            otic::ast::PrimitiveType::StringType => "String",
        }
        .to_string(),
        otic::ast::Type::Bytes(_) => "bytes".to_string(),
        otic::ast::Type::Array(elem, size, _) => format!("[{}; {}]", format_type(elem), size),
        otic::ast::Type::Vec(elem, _) => format!("Vec<{}>", format_type(elem)),
        otic::ast::Type::Map(k, v, _) => format!("Map<{}, {}>", format_type(k), format_type(v)),
        otic::ast::Type::Named(path) => path
            .iter()
            .map(|i| i.name.as_str())
            .collect::<Vec<_>>()
            .join("::"),
        otic::ast::Type::Tuple(types, _) => {
            let inner: Vec<String> = types.iter().map(format_type).collect();
            format!("({})", inner.join(", "))
        }
    }
}
