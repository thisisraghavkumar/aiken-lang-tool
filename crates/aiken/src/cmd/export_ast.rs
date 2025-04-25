use aiken_lang::{ast::ModuleKind, expr::UntypedExpr, parser};
use miette::{NamedSource, Report, Result};
use serde::Serialize;
use serde_json;
use std::{fs, path::PathBuf};

#[derive(clap::Args)]
/// Export AST from Aiken files to JSON format for analysis
pub struct Args {
    /// Path to project or individual files
    paths: Vec<String>,

    /// Output directory for the AST files
    #[clap(short = 'o', long)]
    output_dir: PathBuf,
    
    /// Export detailed expression information
    #[clap(short = 'd', long)]
    detailed: bool,
}

// We'll create our own serializable AST representation
#[derive(Serialize)]
struct SerializableModule {
    name: String,
    kind: String,
    definitions: Vec<SerializableDefinition>,
    doc_comments: Option<Vec<String>>,
    source_file: String,
}

#[derive(Serialize)]
struct SerializableDefinition {
    kind: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_args: Option<Vec<SerializableArgument>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_constructors: Option<Vec<SerializableConstructor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<SerializableExpression>,
    location: SerializableSpan,
    doc_comments: Option<Vec<String>>,
}

#[derive(Serialize)]
struct SerializableArgument {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotation: Option<SerializableTypeAnnotation>,
}

#[derive(Serialize)]
struct SerializableConstructor {
    name: String,
    fields: Vec<SerializableField>,
}

#[derive(Serialize)]
struct SerializableField {
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotation: Option<SerializableTypeAnnotation>,
}

#[derive(Serialize)]
struct SerializableTypeAnnotation {
    kind: String,
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    arguments: Vec<SerializableTypeAnnotation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    location: SerializableSpan,
}

#[derive(Serialize)]
struct SerializableExpression {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sub_expressions: Vec<SerializableExpression>,
    location: SerializableSpan,
}

#[derive(Serialize)]
struct SerializableSpan {
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct SerializablePattern {
    kind: String,
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    arguments: Vec<SerializablePatternArg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    location: SerializableSpan,
}

#[derive(Serialize)]
struct SerializablePatternArg {
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    value: SerializablePatternValue,
    location: SerializableSpan,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum SerializablePatternValue {
    Discard { name: String },
    Variable { name: String },
    Constructor { 
        name: String, 
        #[serde(skip_serializing_if = "Vec::is_empty")]
        arguments: Vec<SerializablePatternArg> 
    },
    Tuple { 
        #[serde(skip_serializing_if = "Vec::is_empty")]
        elements: Vec<SerializablePatternValue> 
    },
    List { 
        #[serde(skip_serializing_if = "Vec::is_empty")]
        elements: Vec<SerializablePatternValue>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tail: Option<Box<SerializablePatternValue>> 
    },
}

pub fn exec(
    Args { paths, output_dir, detailed }: Args,
) -> Result<()> {
    // Create output directory if it doesn't exist
    fs::create_dir_all(&output_dir).map_err(|e| {
        miette::Error::msg(format!(
            "Failed to create output directory {}: {}",
            output_dir.display(),
            e
        ))
    })?;

    // Process individual files or whole project
    for path_str in paths {
        let path = PathBuf::from(&path_str);
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "ak") {
            export_file(&path, &output_dir, detailed)?;
        } else if path.is_dir() {
            export_project_files(&path, &output_dir, detailed)?;
        } else {
            eprintln!("Skipping invalid path: {}", path_str);
        }
    }

    Ok(())
}

fn export_file(file_path: &PathBuf, output_dir: &PathBuf, detailed: bool) -> Result<()> {
    // Read the file
    let code = fs::read_to_string(file_path).map_err(|e| {
        miette::Error::msg(format!("Failed to read file {}: {}", file_path.display(), e))
    })?;

    // Parse the file and get AST
    let kind = if file_path.to_string_lossy().contains("validators") {
        ModuleKind::Validator
    } else {
        ModuleKind::Lib
    };

    match parser::module(&code, kind) {
        Ok((ast, _extra)) => {
            // Determine output file name
            let file_name = file_path.file_name().unwrap().to_string_lossy();
            let output_path = output_dir.join(format!("{}.ast.json", file_name));
            
            // Convert to our serializable representation
            let serializable_module = convert_to_serializable_module(&ast, file_path, detailed);
            
            // Serialize to JSON and write to file
            let json = serde_json::to_string_pretty(&serializable_module).map_err(|e| {
                miette::Error::msg(format!("Failed to serialize AST to JSON: {}", e))
            })?;
            
            fs::write(&output_path, json).map_err(|e| {
                miette::Error::msg(format!(
                    "Failed to write AST to file {}: {}",
                    output_path.display(),
                    e
                ))
            })?;
            
            println!("Exported AST for {} to {}", file_path.display(), output_path.display());
            Ok(())
        }
        Err(errors) => {
            let named_source_str = file_path.display().to_string();
            let code_str = code.clone();
            for error in errors {
                let named_source = NamedSource::new(named_source_str.clone(), code_str.clone());
                let report = Report::new(error).with_source_code(named_source);
                eprintln!("{:?}", report);
            }
            miette::bail!("Failed to parse file: {}", file_path.display())
        }
    }
}

fn convert_to_serializable_module(ast: &aiken_lang::ast::UntypedModule, file_path: &PathBuf, detailed: bool) -> SerializableModule {
    let mut definitions = Vec::new();
    
    // Extract doc comments if available
    let module_docs = if !ast.docs.is_empty() {
        Some(ast.docs.clone())
    } else {
        None
    };
    
    for def in &ast.definitions {
        match def {
            aiken_lang::ast::Definition::Fn(function) => {
                // Extract function arguments with type annotations
                let args = function.arguments.iter()
                    .map(|arg| {
                        let arg_name = match &arg.arg_name {
                            aiken_lang::ast::ArgName::Named { name, .. } => name.clone(),
                            _ => "_".to_string(),
                        };
                        
                        // Convert the annotation to structured form if present
                        let annotation = arg.annotation.as_ref().map(serialize_annotation);
                        
                        SerializableArgument {
                            name: arg_name,
                            annotation,
                        }
                    })
                    .collect();
                
                // Extract function body if detailed mode is enabled
                let body = if detailed {
                    Some(serialize_expression(&function.body))
                } else {
                    None
                };
                
                // Extract function doc comments
                let docs = function.doc.as_ref().map(|doc| vec![doc.clone()]);
                
                definitions.push(SerializableDefinition {
                    kind: "Function".to_string(),
                    name: function.name.clone(),
                    function_args: Some(args),
                    data_constructors: None,
                    body,
                    location: SerializableSpan {
                        start: function.location.start,
                        end: function.location.end,
                    },
                    doc_comments: docs,
                });
            },
            aiken_lang::ast::Definition::DataType(data_type) => {
                let constructors = data_type.constructors.iter()
                    .map(|constructor| {
                        SerializableConstructor {
                            name: constructor.name.clone(),
                            fields: constructor.arguments.iter()
                                .map(|arg| {
                                    // Serialize the annotation properly instead of as a string
                                    let annotation = Some(serialize_annotation(&arg.annotation));
                                    
                                    SerializableField {
                                        name: arg.label.clone(),
                                        annotation,
                                    }
                                })
                                .collect(),
                        }
                    })
                    .collect();
                
                // Extract data type doc comments
                let docs = data_type.doc.as_ref().map(|doc| vec![doc.clone()]);
                
                definitions.push(SerializableDefinition {
                    kind: "DataType".to_string(),
                    name: data_type.name.clone(),
                    function_args: None,
                    data_constructors: Some(constructors),
                    body: None,
                    location: SerializableSpan {
                        start: data_type.location.start,
                        end: data_type.location.end,
                    },
                    doc_comments: docs,
                });
            },
            aiken_lang::ast::Definition::Validator(validator) => {
                // Extract validator arguments with type annotations
                let args = validator.fun.arguments.iter()
                    .map(|arg| {
                        let arg_name = match &arg.arg_name {
                            aiken_lang::ast::ArgName::Named { name, .. } => name.clone(),
                            _ => "_".to_string(),
                        };
                        
                        // Convert the annotation to structured form if present
                        let annotation = arg.annotation.as_ref().map(serialize_annotation);
                        
                        SerializableArgument {
                            name: arg_name,
                            annotation,
                        }
                    })
                    .collect();
                
                // Extract validator body if detailed mode is enabled
                let body = if detailed {
                    Some(serialize_expression(&validator.fun.body))
                } else {
                    None
                };
                
                // Extract validator doc comments
                let docs = validator.fun.doc.as_ref().map(|doc| vec![doc.clone()]);
                
                definitions.push(SerializableDefinition {
                    kind: "Validator".to_string(),
                    name: validator.fun.name.clone(),
                    function_args: Some(args),
                    data_constructors: None,
                    body,
                    location: SerializableSpan {
                        start: validator.location.start,
                        end: validator.location.end,
                    },
                    doc_comments: docs,
                });
            },
            // Add other definition types as needed
            _ => {
                // Skip other definition types for now
            }
        }
    }
    
    SerializableModule {
        name: ast.name.clone(),
        kind: match ast.kind {
            ModuleKind::Lib => "Library".to_string(),
            ModuleKind::Validator => "Validator".to_string(),
        },
        definitions,
        doc_comments: module_docs,
        source_file: file_path.to_string_lossy().to_string(),
    }
}

fn serialize_expression(expr: &UntypedExpr) -> SerializableExpression {
    match expr {
        UntypedExpr::UInt { location, value, .. } => {
            SerializableExpression {
                kind: "Integer".to_string(),
                value: Some(serde_json::Value::String(value.clone())),
                sub_expressions: Vec::new(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::String { location, value } => {
            SerializableExpression {
                kind: "String".to_string(),
                value: Some(serde_json::Value::String(value.clone())),
                sub_expressions: Vec::new(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Var { location, name } => {
            SerializableExpression {
                kind: "Variable".to_string(),
                value: Some(serde_json::Value::String(name.clone())),
                sub_expressions: Vec::new(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Call { location, fun, arguments } => {
            let mut sub_expressions = vec![serialize_expression(fun)];
            
            for arg in arguments {
                sub_expressions.push(serialize_expression(&arg.value));
            }
            
            SerializableExpression {
                kind: "FunctionCall".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::If { location, branches, final_else } => {
            let mut sub_expressions = Vec::new();
            
            for branch in branches.iter() {
                sub_expressions.push(serialize_expression(&branch.condition));
                sub_expressions.push(serialize_expression(&branch.body));
            }
            
            sub_expressions.push(serialize_expression(final_else));
            
            SerializableExpression {
                kind: "IfExpression".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::BinOp { location, name, left, right } => {
            SerializableExpression {
                kind: "BinaryOperation".to_string(),
                value: Some(serde_json::Value::String(format!("{:?}", name))),
                sub_expressions: vec![
                    serialize_expression(left),
                    serialize_expression(right),
                ],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Assignment { location, value, pattern, kind, .. } => {
            // Convert assignment kind to string
            let kind_str = match kind {
                aiken_lang::ast::AssignmentKind::Let => "Let",
                aiken_lang::ast::AssignmentKind::Expect => "Expect",
            };
            
            let mut json_value = serde_json::Map::new();
            // Use the new pattern serialization instead of string representation
            json_value.insert("kind".to_string(), serde_json::Value::String(kind_str.to_string()));
            
            let serialized_pattern = serialize_pattern(pattern);
            let pattern_json = serde_json::to_value(serialized_pattern).unwrap_or(serde_json::Value::Null);
            json_value.insert("pattern".to_string(), pattern_json);
            
            SerializableExpression {
                kind: "Assignment".to_string(),
                value: Some(serde_json::Value::Object(json_value)),
                sub_expressions: vec![serialize_expression(value)],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::List { location, elements, tail } => {
            let mut sub_expressions = elements.iter().map(serialize_expression).collect::<Vec<_>>();
            
            if let Some(tail_expr) = tail {
                sub_expressions.push(serialize_expression(tail_expr));
            }
            
            SerializableExpression {
                kind: "List".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Tuple { location, elems } => {
            let sub_expressions = elems.iter().map(serialize_expression).collect();
            
            SerializableExpression {
                kind: "Tuple".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::FieldAccess { location, label, container } => {
            SerializableExpression {
                kind: "FieldAccess".to_string(),
                value: Some(serde_json::Value::String(label.clone())),
                sub_expressions: vec![serialize_expression(container)],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Sequence { location, expressions } => {
            let sub_expressions = expressions.iter().map(serialize_expression).collect();
            
            SerializableExpression {
                kind: "Sequence".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::When { location, subject, clauses } => {
            let mut sub_expressions = vec![serialize_expression(subject)];
            
            // Add clauses as sub-expressions
            for clause in clauses {
                let pattern_expr = SerializableExpression {
                    kind: "Pattern".to_string(),
                    value: Some(serde_json::Value::String(format!("{:?}", clause.patterns))),
                    sub_expressions: Vec::new(),
                    location: SerializableSpan {
                        start: clause.location.start,
                        end: clause.location.end,
                    },
                };
                
                sub_expressions.push(pattern_expr);
                sub_expressions.push(serialize_expression(&clause.then));
            }
            
            SerializableExpression {
                kind: "When".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Fn { location, arguments, body, .. } => {
            let mut sub_expressions = vec![];
            
            // Add body expression
            sub_expressions.push(serialize_expression(body));
            
            // Create a simple representation of function arguments
            let args_value = arguments.iter()
                .map(|arg| {
                    let name = match &arg.arg_name {
                        aiken_lang::ast::ArgName::Named { name, .. } => name.clone(),
                        aiken_lang::ast::ArgName::Discarded { name, .. } => name.clone(),
                    };
                    serde_json::Value::String(name)
                })
                .collect::<Vec<_>>();
            
            SerializableExpression {
                kind: "Function".to_string(),
                value: Some(serde_json::Value::Array(args_value)),
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::ByteArray { location, bytes, .. } => {
            let hex_string = hex::encode(bytes);
            
            SerializableExpression {
                kind: "ByteArray".to_string(),
                value: Some(serde_json::Value::String(hex_string)),
                sub_expressions: Vec::new(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::TraceIfFalse { location, value } => {
            SerializableExpression {
                kind: "TraceIfFalse".to_string(),
                value: None,
                sub_expressions: vec![serialize_expression(value)],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::Trace { location, then, text, kind, .. } => {
            let kind_str = match kind {
                aiken_lang::ast::TraceKind::Trace => "Trace",
                aiken_lang::ast::TraceKind::Todo => "Todo",
                aiken_lang::ast::TraceKind::Error => "Error",
            };
            
            SerializableExpression {
                kind: "Trace".to_string(),
                value: Some(serde_json::Value::String(kind_str.to_string())),
                sub_expressions: vec![
                    serialize_expression(text),
                    serialize_expression(then),
                ],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::UnOp { location, op, value } => {
            let op_str = match op {
                aiken_lang::ast::UnOp::Not => "Not",
                aiken_lang::ast::UnOp::Negate => "Negate",
            };
            
            SerializableExpression {
                kind: "UnaryOperation".to_string(),
                value: Some(serde_json::Value::String(op_str.to_string())),
                sub_expressions: vec![serialize_expression(value)],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::TupleIndex { location, index, tuple } => {
            SerializableExpression {
                kind: "TupleIndex".to_string(),
                value: Some(serde_json::Value::Number(serde_json::Number::from(*index))),
                sub_expressions: vec![serialize_expression(tuple)],
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::ErrorTerm { location } => {
            SerializableExpression {
                kind: "ErrorTerm".to_string(),
                value: None,
                sub_expressions: Vec::new(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::PipeLine { expressions, one_liner } => {
            let sub_expressions = expressions.iter().map(serialize_expression).collect();
            
            let mut json_value = serde_json::Map::new();
            json_value.insert("one_liner".to_string(), serde_json::Value::Bool(*one_liner));
            
            SerializableExpression {
                kind: "Pipeline".to_string(),
                value: Some(serde_json::Value::Object(json_value)),
                sub_expressions,
                location: SerializableSpan {
                    start: expressions.first().location().start,
                    end: expressions.last().location().end,
                },
            }
        },
        UntypedExpr::RecordUpdate { location, constructor, spread, arguments } => {
            let mut sub_expressions = vec![serialize_expression(constructor)];
            
            // Add the spread expression
            let spread_expr = SerializableExpression {
                kind: "Spread".to_string(),
                value: None,
                sub_expressions: vec![serialize_expression(&spread.base)],
                location: SerializableSpan {
                    start: spread.location.start,
                    end: spread.location.end,
                },
            };
            sub_expressions.push(spread_expr);
            
            // Add argument expressions
            for arg in arguments {
                let arg_expr = SerializableExpression {
                    kind: "RecordUpdateArg".to_string(),
                    value: Some(serde_json::Value::String(arg.label.clone())),
                    sub_expressions: vec![serialize_expression(&arg.value)],
                    location: SerializableSpan {
                        start: arg.location.start,
                        end: arg.location.end,
                    },
                };
                sub_expressions.push(arg_expr);
            }
            
            SerializableExpression {
                kind: "RecordUpdate".to_string(),
                value: None,
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        UntypedExpr::LogicalOpChain { location, kind, expressions } => {
            let kind_str = match kind {
                aiken_lang::ast::LogicalOpChainKind::And => "And",
                aiken_lang::ast::LogicalOpChainKind::Or => "Or",
            };
            
            let sub_expressions = expressions.iter().map(serialize_expression).collect();
            
            SerializableExpression {
                kind: "LogicalOpChain".to_string(),
                value: Some(serde_json::Value::String(kind_str.to_string())),
                sub_expressions,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        // If we missed any variant, use this fallback but with a clearer structure
        _ => {
            let fallback_type = format!("{:?}", expr);
            let expr_type = if let Some(idx) = fallback_type.find('{') {
                fallback_type[0..idx].trim().to_string()
            } else {
                "Unknown".to_string()
            };
            
            SerializableExpression {
                kind: expr_type,
                value: Some(serde_json::Value::String(fallback_type)),
                sub_expressions: Vec::new(),
                location: SerializableSpan {
                    start: expr.location().start,
                    end: expr.location().end,
                },
            }
        }
    }
}

fn serialize_pattern(pattern: &aiken_lang::ast::UntypedPattern) -> SerializablePattern {
    match pattern {
        aiken_lang::ast::Pattern::Constructor { name, location, arguments, module, .. } => {
            SerializablePattern {
                kind: "Constructor".to_string(),
                name: name.clone(),
                arguments: arguments.iter().map(serialize_pattern_arg).collect(),
                module: module.clone(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Pattern::Var { name, location } => {
            SerializablePattern {
                kind: "Variable".to_string(),
                name: name.clone(),
                arguments: Vec::new(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Pattern::Discard { name, location } => {
            SerializablePattern {
                kind: "Discard".to_string(),
                name: name.clone(),
                arguments: Vec::new(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Pattern::List { elements, tail, location } => {
            SerializablePattern {
                kind: "List".to_string(),
                name: "List".to_string(),
                arguments: elements.iter().enumerate().map(|(i, elem)| {
                    SerializablePatternArg {
                        label: Some(i.to_string()),
                        value: serialize_pattern_value(elem),
                        location: SerializableSpan {
                            start: elem.location().start,
                            end: elem.location().end,
                        },
                    }
                }).collect(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Pattern::Tuple { elems, location } => {
            SerializablePattern {
                kind: "Tuple".to_string(),
                name: "Tuple".to_string(),
                arguments: elems.iter().enumerate().map(|(i, elem)| {
                    SerializablePatternArg {
                        label: Some(i.to_string()),
                        value: serialize_pattern_value(elem),
                        location: SerializableSpan {
                            start: elem.location().start,
                            end: elem.location().end,
                        },
                    }
                }).collect(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        _ => {
            // Fallback for any pattern types we missed
            SerializablePattern {
                kind: "Other".to_string(),
                name: format!("{:?}", pattern),
                arguments: Vec::new(),
                module: None,
                location: SerializableSpan {
                    start: pattern.location().start,
                    end: pattern.location().end,
                },
            }
        }
    }
}

fn serialize_pattern_arg(arg: &aiken_lang::ast::CallArg<aiken_lang::ast::UntypedPattern>) -> SerializablePatternArg {
    SerializablePatternArg {
        label: arg.label.clone(),
        value: serialize_pattern_value(&arg.value),
        location: SerializableSpan {
            start: arg.location.start,
            end: arg.location.end,
        },
    }
}

fn serialize_pattern_value(pattern: &aiken_lang::ast::UntypedPattern) -> SerializablePatternValue {
    match pattern {
        aiken_lang::ast::Pattern::Constructor { name, arguments, .. } => {
            SerializablePatternValue::Constructor { 
                name: name.clone(),
                arguments: arguments.iter().map(serialize_pattern_arg).collect(),
            }
        },
        aiken_lang::ast::Pattern::Var { name, .. } => {
            SerializablePatternValue::Variable { name: name.clone() }
        },
        aiken_lang::ast::Pattern::Discard { name, .. } => {
            SerializablePatternValue::Discard { name: name.clone() }
        },
        aiken_lang::ast::Pattern::List { elements, tail, .. } => {
            let mut elements_vec = Vec::new();
            for elem in elements {
                elements_vec.push(serialize_pattern_value(elem));
            }
            
            let tail_pattern = tail.as_ref().map(|t| Box::new(serialize_pattern_value(t)));
            
            SerializablePatternValue::List { 
                elements: elements_vec,
                tail: tail_pattern,
            }
        },
        aiken_lang::ast::Pattern::Tuple { elems, .. } => {
            let mut elements_vec = Vec::new();
            for elem in elems {
                elements_vec.push(serialize_pattern_value(elem));
            }
            
            SerializablePatternValue::Tuple { 
                elements: elements_vec,
            }
        },
        _ => SerializablePatternValue::Variable { name: format!("Unsupported_{:?}", pattern) },
    }
}

fn serialize_annotation(annotation: &aiken_lang::ast::Annotation) -> SerializableTypeAnnotation {
    match annotation {
        aiken_lang::ast::Annotation::Constructor { name, location, arguments, module } => {
            SerializableTypeAnnotation {
                kind: "Constructor".to_string(),
                name: name.clone(),
                arguments: arguments.iter().map(serialize_annotation).collect(),
                module: module.clone(),
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Annotation::Fn { location, arguments, ret } => {
            let mut args = arguments.iter().map(serialize_annotation).collect::<Vec<_>>();
            let return_annotation = serialize_annotation(ret);
            
            SerializableTypeAnnotation {
                kind: "Function".to_string(),
                name: "fn".to_string(),
                arguments: args,
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Annotation::Var { name, location } => {
            SerializableTypeAnnotation {
                kind: "Variable".to_string(),
                name: name.clone(),
                arguments: Vec::new(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Annotation::Hole { name, location } => {
            SerializableTypeAnnotation {
                kind: "Hole".to_string(),
                name: name.clone(),
                arguments: Vec::new(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
        aiken_lang::ast::Annotation::Tuple { elems, location } => {
            SerializableTypeAnnotation {
                kind: "Tuple".to_string(),
                name: "Tuple".to_string(),
                arguments: elems.iter().map(serialize_annotation).collect(),
                module: None,
                location: SerializableSpan {
                    start: location.start,
                    end: location.end,
                },
            }
        },
    }
}

fn export_project_files(project_dir: &PathBuf, output_dir: &PathBuf, detailed: bool) -> Result<()> {
    // Find all Aiken files in the project
    let aiken_files = find_aiken_files(project_dir)?;
    
    for file_path in aiken_files {
        export_file(&file_path, output_dir, detailed)?;
    }
    
    Ok(())
}

fn find_aiken_files(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut aiken_files = Vec::new();
    
    let entries = fs::read_dir(dir).map_err(|e| {
        miette::Error::msg(format!("Failed to read directory {}: {}", dir.display(), e))
    })?;
    
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.is_dir() {
                // Skip target directory
                if path.file_name().map_or(false, |name| name == "target") {
                    continue;
                }
                let mut subdir_files = find_aiken_files(&path)?;
                aiken_files.append(&mut subdir_files);
            } else if path.extension().map_or(false, |ext| ext == "ak") {
                aiken_files.push(path);
            }
        }
    }
    
    Ok(aiken_files)
} 