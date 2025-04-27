# CLI

This is the crate that contains the aiken command line application
which bundles together all the other crates in this project.

## Install

`cargo install aiken`

## Commands

### Export AST

The `export-ast` command allows you to export the Abstract Syntax Tree (AST) of Aiken files to JSON format for further analysis or processing.

```
aiken export-ast [OPTIONS] [PATHS]...
```

#### Options:
- `-o, --output-dir <OUTPUT_DIR>`: Output directory for the AST files
- `-d, --detailed`: Export detailed expression information

#### Recent Enhancements:

The AST exporter now includes complete support for `use` statements in the exported JSON, which is crucial for understanding module dependencies and imports. Each file is processed independently, and its AST includes all the necessary information about imported modules.

The exported AST for `use` statements will contain:
- The module path being imported
- Any alias (`as` name) applied to the import
- The list of any unqualified imports with their locations and aliases

This improvement enables downstream tools to better understand the relationships between modules and properly resolve references to imported definitions.

In addition, all definition types are now supported in the export, including:
- Functions
- Data types
- Type aliases
- Module constants
- Validators
- Tests
- Use statements

This makes the export-ast command a comprehensive tool for analyzing Aiken code structure programmatically.
