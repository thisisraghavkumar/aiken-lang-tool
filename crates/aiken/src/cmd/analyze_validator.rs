use aiken_lang::{
    ast::{Definition, ModuleKind, Tracing, TypedValidator, Function, Arg, Span, AssignmentKind, BinOp},
    expr::TypedExpr,
    tipo::Type,
};
use aiken_project::watch::with_project;
use std::{collections::{HashMap, HashSet}, fmt::{self, Display}, path::PathBuf, process, rc::Rc};

/// Analyze validator code using symbolic execution
#[derive(clap::Args)]
pub struct Args {
    /// Path to project
    directory: Option<PathBuf>,

    /// Deny warnings; warnings will be treated as errors
    #[clap(short = 'D', long)]
    deny: bool,
}

// Types of security patterns we're looking for
#[derive(Debug, Clone, PartialEq)]
enum SecurityPatternKind {
    InputTokenCountComparison,
    DuplicateInputCheck,
    // Other security patterns could be added here
}

// Describes a security finding in the code
#[derive(Debug, Clone)]
struct SecurityFinding {
    kind: SecurityPatternKind,
    confidence: u8,  // 0-100
    location: Span,
    description: String,
}

// Origin of a symbolic value - what it represents from the script context
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ValueOrigin {
    // The ScriptContext parameter itself
    ScriptContext,
    // The transaction from ctx.transaction
    Transaction,
    // The list of inputs from ctx.transaction.inputs
    TransactionInputs,
    // The input refering to self from ctx.transaction.inputs
    InputToken,
    // The output record in the input refering to self
    InputTokenOutput,
    // The address of the output record refering to self
    InputTokenAddress,
    // Script purpose from ctx.purpose
    Purpose,
    // Output reference from ctx.purpose (if it's a Spend)
    OutputReference,
    // Other origin not directly related to script context
    Other(String),
    // Count of tokens in a list
    TokenCount,
    // Unknown origin
    Unknown,
}

// Represents a value during symbolic execution
#[derive(Debug, Clone)]
struct SymbolicValue {
    // Where this value came from (e.g., ScriptContext.Transaction.Inputs)
    origin: ValueOrigin,
    // Type information
    value_type: Rc<Type>,
    // For values derived through function calls or operations
    derived_from: Vec<ValueOrigin>,
    // If this represents a condition/predicate that compares addresses
    is_address_comparison: bool,
}

impl SymbolicValue {
    // Create a new value with known origin
    fn new(origin: ValueOrigin, value_type: Rc<Type>) -> Self {
        Self {
            origin,
            value_type,
            derived_from: vec![],
            is_address_comparison: false,
        }
    }
    
    // Create a value derived from other values
    fn derived(origin: ValueOrigin, value_type: Rc<Type>, derived_from: Vec<ValueOrigin>) -> Self {
        Self {
            origin,
            value_type,
            derived_from,
            is_address_comparison: false,
        }
    }
    
    // Create an unknown value
    fn unknown(value_type: Rc<Type>) -> Self {
        Self {
            origin: ValueOrigin::Unknown,
            value_type,
            derived_from: vec![],
            is_address_comparison: false,
        }
    }
    
    // Check if this value is derived from transaction inputs
    fn is_derived_from_inputs(&self) -> bool {
        self.origin == ValueOrigin::TransactionInputs || 
        self.derived_from.contains(&ValueOrigin::TransactionInputs)
    }
    
    // Check if this value is derived from output reference
    fn is_derived_from_output_reference(&self) -> bool {
        self.origin == ValueOrigin::OutputReference || 
        self.derived_from.contains(&ValueOrigin::OutputReference)
    }
    
    // Mark this value as an address comparison
    fn as_address_comparison(mut self) -> Self {
        self.is_address_comparison = true;
        self
    }
}

// Implement Display for SymbolicValue
impl Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Start with the origin
        match &self.origin {
            ValueOrigin::ScriptContext => write!(f, "ScriptContext")?,
            ValueOrigin::Transaction => write!(f, "Transaction")?,
            ValueOrigin::TransactionInputs => write!(f, "TransactionInputs")?,
            ValueOrigin::InputToken => write!(f, "InputToken")?,
            ValueOrigin::InputTokenOutput => write!(f, "InputTokenOutput")?,
            ValueOrigin::InputTokenAddress => write!(f, "InputTokenAddress")?,
            ValueOrigin::Purpose => write!(f, "Purpose")?,
            ValueOrigin::OutputReference => write!(f, "OutputReference")?,
            ValueOrigin::TokenCount => write!(f, "TokenCount")?,
            ValueOrigin::Other(s) => write!(f, "Other({})", s)?,
            ValueOrigin::Unknown => write!(f, "Unknown")?,
        }
        
        // Show type (shortened version)
        //let type_str = format!("{:?}", self.value_type);
        //let simplified_type = if type_str.len() > 25 {
            // Truncate if too long for display
        //    format!("{}...", &type_str[0..22])
        //} else {
        //    type_str
        //};
        //write!(f, ":{}", simplified_type)?;
        
        // Show derived_from information if any
        if !self.derived_from.is_empty() {
            write!(f, " derived_from:[")?;
            for (i, origin) in self.derived_from.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                match origin {
                    ValueOrigin::ScriptContext => write!(f, "ScriptContext")?,
                    ValueOrigin::Transaction => write!(f, "Transaction")?,
                    ValueOrigin::TransactionInputs => write!(f, "TransactionInputs")?,
                    ValueOrigin::InputToken => write!(f, "InputToken")?,
                    ValueOrigin::InputTokenOutput => write!(f, "InputTokenOutput")?,
                    ValueOrigin::InputTokenAddress => write!(f, "InputTokenAddress")?,
                    ValueOrigin::Purpose => write!(f, "Purpose")?,
                    ValueOrigin::OutputReference => write!(f, "OutputReference")?,
                    ValueOrigin::TokenCount => write!(f, "TokenCount")?,
                    ValueOrigin::Other(s) => write!(f, "Other({})", s)?,
                    ValueOrigin::Unknown => write!(f, "Unknown")?,
                }
            }
            write!(f, "]")?;
        }
        
        // Add indicator if this is an address comparison
        // if self.is_address_comparison {
        //     write!(f, " (address_comparison)")?;
        // }
        
        Ok(())
    }
}

// Predicate/condition encountered during symbolic execution
#[derive(Debug, Clone)]
enum SymbolicCondition {
    Equals {
        left: SymbolicValue,
        right: SymbolicValue,
        location: Span,
    },
    NotEquals {
        left: SymbolicValue,
        right: SymbolicValue,
        location: Span,
    },
    // Operation on a list like find, count, etc.
    ListOperation {
        operation: String,
        list: SymbolicValue,
        predicate: Option<SymbolicValue>,
        location: Span,
    },
    // Expect statement or assert
    Assertion {
        condition: Box<SymbolicCondition>,
        location: Span,
    },
    // Custom check
    Custom {
        description: String,
        relates_to_inputs: bool,
        relates_to_output_ref: bool,
        location: Span,
    },
}

// Environment that tracks variable bindings during symbolic execution
#[derive(Debug, Clone)]
struct SymbolicEnvironment {
    // Map variable names to their symbolic values
    variables: HashMap<String, SymbolicValue>,
    // Name of the ScriptContext parameter (might not always be "ctx")
    script_context_name: Option<String>,
    // Current conditions that hold in this environment
    conditions: Vec<SymbolicCondition>,
    // Current function level (0 = top-level validator, 1 = inside a function call)
    function_level: Option<u8>,
}

impl SymbolicEnvironment {
    // Create a new empty environment
    fn new() -> Self {
        Self {
            variables: HashMap::new(),
            script_context_name: None,
            conditions: Vec::new(),
            function_level: None,
        }
    }
    
    // Set the script context parameter name
    fn set_script_context(&mut self, name: String, context_type: Rc<Type>) {
        self.script_context_name = Some(name.clone());
        self.variables.insert(name, SymbolicValue::new(ValueOrigin::ScriptContext, context_type));
    }
    
    // Add a variable to the environment
    fn add_variable(&mut self, name: String, value: SymbolicValue) {
        println!("DEBUG: Adding variable: {} = {}", name, value);
        self.variables.insert(name, value);
    }
    
    // Add a condition to the environment
    fn add_condition(&mut self, condition: SymbolicCondition) {
        self.conditions.push(condition);
    }
    
    // Debug print the environment in a well-formatted table
    fn debug_print(&self) {
        println!("\n=== SYMBOLIC ENVIRONMENT STATE ===");
        
        // Print script context if present
        if let Some(ctx) = &self.script_context_name {
            println!("ScriptContext parameter: {}", ctx);
        } else {
            println!("ScriptContext not identified");
        }
        
        // Print variables table
        println!("\n--- TRACKED VARIABLES ---");
        println!("{:<40} | {:<40} | {:<40}", "Variable", "Value", "Type");
        println!("{:-<125}", "");
        
        if self.variables.is_empty() {
            println!("No variables tracked yet");
        } else {
            // Sort variables for consistent output
            let mut variables: Vec<(&String, &SymbolicValue)> = self.variables.iter().collect();
            variables.sort_by(|a, b| a.0.cmp(b.0));
            
            for (name, value) in variables {
                // Flag address comparison values
                let name_display = if value.is_address_comparison {
                    format!("{}*", name)  // Add * to mark address comparison
                } else {
                    name.clone()
                };
                
                // Use our Display impl for SymbolicValue
                println!("{:<40} | {:<40} | {:<40}", 
                        name_display, 
                        value, 
                        format!("{:?}", value.value_type));
            }
        }
        
        // Print conditions
        println!("\n--- CONDITIONS ---");
        
        if self.conditions.is_empty() {
            println!("No conditions tracked yet");
        } else {
            for (i, condition) in self.conditions.iter().enumerate() {
                match condition {
                    SymbolicCondition::Equals { left, right, .. } => {
                        println!("{}. EQUALS: {} == {}", 
                                 i+1, left, right);
                    },
                    SymbolicCondition::NotEquals { left, right, .. } => {
                        println!("{}. NOT EQUALS: {} != {}", 
                                 i+1, left, right);
                    },
                    SymbolicCondition::ListOperation { operation, list, predicate, .. } => {
                        let pred_desc = if let Some(p) = predicate {
                            if p.is_address_comparison {
                                format!("{} (address comparison)", p)
                            } else {
                                format!("{}", p)
                            }
                        } else {
                            "(no predicate)".to_string()
                        };
                        
                        println!("{}. LIST.{}: on {} with predicate {}", 
                                 i+1, operation, list, pred_desc);
                    },
                    SymbolicCondition::Assertion { condition, .. } => {
                        println!("{}. ASSERTION: {:?}", i+1, condition);
                    },
                    SymbolicCondition::Custom { description, .. } => {
                        println!("{}. CUSTOM: {}", i+1, description);
                    },
                }
            }
        }
        
        // Security findings summary
        let has_duplicate_check = self.has_duplicate_input_check();
        
        println!("\n--- SECURITY ANALYSIS ---");
        if has_duplicate_check {
            println!("✅ Duplicate input checking detected");
        } else {
            println!("❌ No duplicate input checking detected");
        }
        
        println!("{:-<125}", "");
    }
    
    // Check if the environment contains checks for duplicate inputs
    fn has_duplicate_input_check(&self) -> bool {
        for condition in &self.conditions {
            match condition {
                SymbolicCondition::Equals { left, right, .. } => {
                    // Check if it's comparing a count to 1
                    if self.is_count_equals_one(left, right) {
                        return true;
                    }
                },
                SymbolicCondition::ListOperation { operation, list, predicate, .. } => {
                    // Check if it's counting inputs filtered by address
                    if operation == "count" && list.is_derived_from_inputs() {
                        if let Some(pred) = predicate {
                            if pred.is_address_comparison {
                                return true;
                            }
                        }
                    }
                },
                SymbolicCondition::Assertion { condition, .. } => {
                    // Check assertions
                    match &**condition {
                        SymbolicCondition::Equals { left, right, .. } => {
                            if self.is_count_equals_one(left, right) {
                                return true;
                            }
                        },
                        _ => {}
                    }
                },
                _ => {}
            }
        }
        false
    }
    
    // Helper to check if a condition is comparing a count to 1
    fn is_count_equals_one(&self, left: &SymbolicValue, right: &SymbolicValue) -> bool {
        // Check if one side is a count and the other is 1
        // This is a simplified version - would need more logic
        // for a real implementation
        false
    }
}

// Result of symbolic execution of an expression
#[derive(Debug, Clone)]
struct ExprResult {
    // The resulting symbolic value
    value: SymbolicValue,
    // Environment after execution
    environment: SymbolicEnvironment,
    // Security findings detected during execution
    findings: Vec<SecurityFinding>,
    // Set of symbolic values that are used in this expression
    uses: HashSet<ValueOrigin>,
    // Tracks whether this expression uses ScriptContext.purpose
    uses_purpose: bool,
    // Tracks whether this expression uses Transaction.inputs
    uses_inputs: bool,
    // Location information for reporting
    location: Option<Span>,
    // Current function call level (0 = top-level validator, 1 = inside a function call)
    function_level: u8,
}

// Represents an argument in a function signature for analysis
#[derive(Debug, Clone)]
struct FunctionArgument {
    name: String,
    tipo: Rc<Type>,
}

// Store information about a function for symbolic execution
#[derive(Debug, Clone)]
struct FunctionInfo {
    // The fully qualified name (module::function)
    qualified_name: String,
    // The function body
    body: TypedExpr,
    // The function definition containing arguments, return type, etc.
    definition: Function<Rc<Type>, TypedExpr>,
    // The module the function belongs to
    module_name: String,
    // Simplified arguments list for analysis
    arguments: Vec<FunctionArgument>,
    // Return type
    return_type: Option<Rc<Type>>,
    // Is this a validator function?
    is_validator: bool,
    // Index of the script context parameter (-1 if not a validator)
    script_context_param_index: i32,
}

impl FunctionInfo {
    fn new(function: &Function<Rc<Type>, TypedExpr>, module_name: &str) -> Self {
        let qualified_name = format!("{}::{}", module_name, function.name);
        let mut arguments = Vec::new();
        
        // Extract argument information
        for arg in &function.arguments {
            arguments.push(FunctionArgument {
                name: format!("{:?}", arg.arg_name),
                tipo: arg.tipo.clone(),
            });
        }
        
        Self {
            qualified_name,
            body: function.body.clone(),
            definition: function.clone(),
            module_name: module_name.to_string(),
            arguments,
            return_type: Some(function.body.tipo()),
            is_validator: false,
            script_context_param_index: -1,
        }
    }
}

// AST analyzer for validators
struct AstAnalyzer {
    // Store typed validators for analysis
    validators: Vec<TypedValidator>,
    // Store imported functions for analysis (DEPRECATED: use function_table instead)
    functions: HashMap<String, TypedExpr>,
    // Function table with fully qualified names as keys
    function_table: HashMap<String, FunctionInfo>,
}

impl AstAnalyzer {
    fn new() -> Self {
        Self {
            validators: Vec::new(),
            functions: HashMap::new(),
            function_table: HashMap::new(),
        }
    }

    // Add a validator to analyze
    fn add_validator(&mut self, validator: TypedValidator) {
        let validator_name = format!("validator::{}", validator.fun.name);
        println!("  Adding validator: {}", validator.fun.name);
        
        self.validators.push(validator.clone());
        
        // If the validator function is in our function table, mark it
        self.mark_as_validator(&validator_name, &validator);
    }

    // Register functions from modules (DEPRECATED: use register_function_with_module instead)
    fn register_function(&mut self, name: String, body: TypedExpr) {
        self.functions.insert(name, body);
    }
    
    // Register a function with its module name for proper scoping
    fn register_function_with_module(&mut self, function: &Function<Rc<Type>, TypedExpr>, module_name: &str) {
        let function_info = FunctionInfo::new(function, module_name);
        let qualified_name = function_info.qualified_name.clone();
        
        //println!("  Registering function: {}", qualified_name);
        
        self.function_table.insert(qualified_name, function_info);
        
        // For backward compatibility, also add to the old functions map
        self.functions.insert(function.name.clone(), function.body.clone());
    }
    
    // Mark a function as a validator and identify its ScriptContext parameter
    fn mark_as_validator(&mut self, validator_name: &str, validator: &TypedValidator) {
        if let Some(function_info) = self.function_table.get_mut(validator_name) {
            function_info.is_validator = true;
            
            // Identify which parameter is the ScriptContext
            // For Aiken validators, it's typically the third parameter (index 2)
            // but we should check the type to be certain
            if validator.fun.arguments.len() >= 3 {
                // In Aiken, the ScriptContext is typically the last parameter
                let last_idx = validator.fun.arguments.len() - 1;
                let arg = &validator.fun.arguments[last_idx];
                
                // Look at the type name to confirm it's a ScriptContext
                let type_str = format!("{:?}", arg.tipo);
                if type_str.contains("ScriptContext") {
                    function_info.script_context_param_index = last_idx as i32;
                    
                    // Extract just the name from the debug representation
                    let debug_name = format!("{:?}", arg.arg_name);
                    let ctx_name = self.extract_name_from_arg(&debug_name);
                    
                    println!("  Identified ScriptContext parameter '{}' at index {}", 
                             ctx_name, last_idx);
                }
            }
        }
    }
    
    // Initialize symbolic execution for a validator
    fn prepare_symbolic_execution(&self, validator: &TypedValidator) -> SymbolicEnvironment {
        let mut env = SymbolicEnvironment::new();
        
        // Find the ScriptContext parameter
        if validator.fun.arguments.len() >= 3 {
            let last_idx = validator.fun.arguments.len() - 1;
            let arg = &validator.fun.arguments[last_idx];
            
            let type_str = format!("{:?}", arg.tipo);
            if type_str.contains("ScriptContext") {
                // Extract just the name from the debug representation
                let debug_name = format!("{:?}", arg.arg_name);
                let ctx_name = self.extract_name_from_arg(&debug_name);
                
                // Set up the ScriptContext in our environment
                env.set_script_context(ctx_name.clone(), arg.tipo.clone());
                
                // Add transaction
                let transaction_path = format!("{}.transaction", ctx_name);
                env.add_variable(
                    transaction_path.clone(),
                    SymbolicValue::new(ValueOrigin::Transaction, arg.tipo.clone())
                );
                
                // Add transaction.inputs
                let inputs_path = format!("{}.transaction.inputs", ctx_name);
                env.add_variable(
                    inputs_path,
                    SymbolicValue::new(ValueOrigin::TransactionInputs, arg.tipo.clone())
                );
                
                // Add purpose
                let purpose_path = format!("{}.purpose", ctx_name);
                env.add_variable(
                    purpose_path,
                    SymbolicValue::new(ValueOrigin::Purpose, arg.tipo.clone())
                );
            }
        }
        
        env
    }
    
    // Print the function table
    fn print_function_table(&self) {
        println!("\nFunction Table:");
        println!("--------------------------------------------------");
        println!("| {:<30} | {:<15} |", "Qualified Name", "Arguments");
        println!("--------------------------------------------------");
        
        for (qualified_name, function_info) in &self.function_table {
            println!("| {:<30} | {:<15} |", 
                     qualified_name, 
                     function_info.definition.arguments.len());
        }
        println!("--------------------------------------------------");
        println!("Total functions: {}", self.function_table.len());
    }

    // Analyze all collected validators
    fn analyze(&self) {
        println!("\nPerforming static analysis focusing on ScriptContext.purpose and transaction.inputs tracking...");
        println!("Found {} validators to analyze", self.validators.len());
        
        // Create a vector to store validation results for the summary
        let mut validation_results = Vec::new();
        
        // Process each validator
        for validator in &self.validators {
            println!("\nAnalyzing validator: {}", validator.fun.name);
            
            // Initialize environment with ScriptContext
            let mut env = self.prepare_symbolic_execution(validator);
            
            // Execute the validator body
            let execution_result = self.execute_expression(&validator.fun.body, &mut env);
            
            // Report on found ScriptContext.purpose variables
            println!("\nVariables that hold ScriptContext.purpose:");
            let mut found_purpose_vars = false;
            
            for (name, value) in &execution_result.environment.variables {
                if value.origin == ValueOrigin::Purpose {
                    println!("  - {}", name);
                    found_purpose_vars = true;
                }
            }
            
            if !found_purpose_vars {
                println!("  None found");
            }
            
            // Report on found transaction.inputs variables
            println!("\nVariables that hold transaction.inputs:");
            let mut found_inputs_vars = false;
            
            for (name, value) in &execution_result.environment.variables {
                if value.origin == ValueOrigin::TransactionInputs {
                    println!("  - {}", name);
                    found_inputs_vars = true;
                }
            }
            
            if !found_inputs_vars {
                println!("  None found");
            }
            
            // Track expressions that use purpose, inputs, or both
            println!("\nFlagging security-relevant expressions:");
            
            // Vector to store expressions that use purpose only
            let mut purpose_only_expressions = Vec::new();
            // Vector to store expressions that use inputs only
            let mut inputs_only_expressions = Vec::new();
            // Vector to store expressions that use both purpose and inputs
            let mut combined_expressions = Vec::new();
            
            // Analyze all expressions in the validator
            self.collect_expressions_by_usage(
                &validator.fun.body,
                &mut purpose_only_expressions,
                &mut inputs_only_expressions,
                &mut combined_expressions
            );
            
            // Report expressions that use purpose only
            println!("\n1. Expressions that use ONLY ScriptContext.purpose:");
            if purpose_only_expressions.is_empty() {
                println!("  None found");
            } else {
                for expr in &purpose_only_expressions {
                    let location = if let Some(span) = expr.location {
                        format!(" at {}:{}", span.start, span.end)
                    } else {
                        String::new()
                    };
                    println!("  - {:?}{}", expr.value.origin, location);
                }
            }
            
            // Report expressions that use inputs only
            println!("\n2. Expressions that use ONLY Transaction.inputs:");
            if inputs_only_expressions.is_empty() {
                println!("  None found");
            } else {
                for expr in &inputs_only_expressions {
                    let location = if let Some(span) = expr.location {
                        format!(" at {}:{}", span.start, span.end)
                    } else {
                        String::new()
                    };
                    println!("  - {:?}{}", expr.value.origin, location);
                }
            }
            
            // Report expressions that use both purpose and inputs
            println!("\n3. Expressions that use BOTH purpose AND inputs:");
            if combined_expressions.is_empty() {
                println!("  None found");
            } else {
                for expr in &combined_expressions {
                    let location = if let Some(span) = expr.location {
                        format!(" at {}:{}", span.start, span.end)
                    } else {
                        String::new()
                    };
                    println!("  - Expression{}", location);
                }
            }
            
            // Check for InputTokenCountComparison findings
            println!("\nSecurity Check - Token Count Validation:");
            let has_token_count_check = execution_result.findings.iter().any(|finding| 
                finding.kind == SecurityPatternKind::InputTokenCountComparison
            );
            
            if has_token_count_check {
                println!("\x1b[32m✓ PASSED: Token count validation detected\x1b[0m");
                for finding in execution_result.findings.iter().filter(|f| f.kind == SecurityPatternKind::InputTokenCountComparison) {
                    println!("  - Found at line {}: {}", finding.location.start, finding.description);
                }
            } else {
                println!("\x1b[31m✗ ALERT: No token count validation detected - your validator may be vulnerable to double satisfaction attacks\x1b[0m");
                println!("  - Recommendation: Add validation that checks the count of inputs matching specific criteria");
            }
            
            // Check for DuplicateInputCheck findings
            let has_duplicate_check = execution_result.findings.iter().any(|finding| 
                finding.kind == SecurityPatternKind::DuplicateInputCheck
            );
            
            // Store validation results for summary
            validation_results.push((
                validator.fun.name.clone(),
                has_token_count_check,
                has_duplicate_check
            ));
        }
        
        // Print summary table of validation results
        println!("\n\n=================================================================");
        println!("                     SECURITY ANALYSIS SUMMARY                   ");
        println!("=================================================================");
        println!("| {:<30} | {:<20} | {:<20} |", "Validator", "Token Count Check", "Duplicate Input Check");
        println!("|--------------------------------|----------------------|----------------------|");
        
        for (validator_name, has_token_count, has_duplicate) in &validation_results {
            let token_count_status = if *has_token_count {
                "\x1b[32m✓ PASSED\x1b[0m"
            } else {
                "\x1b[31m✗ FAILED\x1b[0m"
            };
            
            let duplicate_check_status = if *has_duplicate {
                "\x1b[32m✓ PASSED\x1b[0m"
            } else {
                "\x1b[31m✗ FAILED\x1b[0m"
            };
            
            println!("| {:<30} | {:<20} | {:<20} |", validator_name, token_count_status, duplicate_check_status);
        }
        
        println!("=================================================================");
        
        // Print recommendations based on summary
        let any_token_count_failed = validation_results.iter().any(|(_, has_token, _)| !has_token);
        let any_duplicate_failed = validation_results.iter().any(|(_, _, has_duplicate)| !has_duplicate);
        
        if any_token_count_failed || any_duplicate_failed {
            println!("\nRECOMMENDATIONS:");
            
            if any_token_count_failed {
                println!("\x1b[31m- Implement token count validation in validators that lack it\x1b[0m");
                println!("  This prevents double satisfaction attacks where the same token is used multiple times");
            }
            
            if any_duplicate_failed {
                println!("\x1b[31m- Add duplicate input checks in validators that lack them\x1b[0m");
                println!("  This ensures the same UTXO cannot be used multiple times in a transaction");
            }
        } else {
            println!("\n\x1b[32mAll validators have implemented the recommended security checks.\x1b[0m");
        }
    }
    
    // Helper method to collect expressions by their usage patterns
    fn collect_expressions_by_usage(
        &self,
        expr: &TypedExpr,
        purpose_only: &mut Vec<ExprResult>,
        inputs_only: &mut Vec<ExprResult>,
        combined: &mut Vec<ExprResult>
    ) {
        // Execute the expression to get usage information
        let mut env = SymbolicEnvironment::new();
        let result = self.execute_expression(expr, &mut env);
        
        // Categorize based on usage
        if result.uses_purpose && result.uses_inputs {
            combined.push(result.clone());
        } else if result.uses_purpose {
            purpose_only.push(result.clone());
        } else if result.uses_inputs {
            inputs_only.push(result.clone());
        }
        
        // Recursively analyze child expressions
        for child in self.get_child_expressions(expr) {
            self.collect_expressions_by_usage(child, purpose_only, inputs_only, combined);
        }
    }
    
    // Analyze an expression for security patterns
    fn check_expression_for_duplicate_inputs(&self, expr: &TypedExpr) -> bool {
        match expr {
            TypedExpr::Call { fun, args, .. } => {
                // First check if the call might be checking for duplicate inputs
                if self.is_duplicate_check_call(fun, args) {
                    return true;
                }
                
                // Recursively check function and arguments
                if self.check_expression_for_duplicate_inputs(fun) {
                    return true;
                }
                
                for arg in args {
                    match arg {
                        aiken_lang::ast::CallArg { value, .. } => {
                            if self.check_expression_for_duplicate_inputs(value) {
                                return true;
                            }
                        }
                    }
                }
                
                false
            },
            
            TypedExpr::BinOp { name, left, right, .. } if matches!(name, 
                BinOp::Eq | BinOp::NotEq | BinOp::LtInt | 
                BinOp::LtEqInt | BinOp::GtEqInt | BinOp::GtInt) => {
                
                // Check if this binary operation is comparing addresses
                if self.is_address_comparison(name, left, right) {
                    return true;
                }
                
                // Continue analysis with sub-expressions
                self.check_expression_for_duplicate_inputs(left) || 
                self.check_expression_for_duplicate_inputs(right)
            },
            
            TypedExpr::Sequence { expressions, .. } => {
                expressions.iter().any(|expr| self.check_expression_for_duplicate_inputs(expr))
            },
            
            TypedExpr::Pipeline { expressions, .. } => {
                expressions.iter().any(|expr| self.check_expression_for_duplicate_inputs(expr))
            },
            
            TypedExpr::If { branches, final_else, .. } => {
                // Check conditions and bodies of all branches
                for branch in branches {
                    if self.check_expression_for_duplicate_inputs(&branch.condition) || 
                       self.check_expression_for_duplicate_inputs(&branch.body) {
                        return true;
                    }
                }
                
                // Check final else branch
                self.check_expression_for_duplicate_inputs(final_else)
            },
            
            TypedExpr::Var { name, .. } => {
                // If we encounter a variable that looks like an imported function, analyze its body
                if let Some(function_body) = self.functions.get(name) {
                    return self.check_expression_for_duplicate_inputs(function_body);
                }
                
                false
            },
            
            TypedExpr::List { elements, tail, .. } => {
                // Check all list elements
                if elements.iter().any(|elem| self.check_expression_for_duplicate_inputs(elem)) {
                    return true;
                }
                
                // Check tail if present
                if let Some(t) = tail {
                    return self.check_expression_for_duplicate_inputs(t);
                }
                
                false
            },
            
            TypedExpr::Assignment { pattern, value, .. } => {
                self.check_expression_for_duplicate_inputs(value)
            },
            
            TypedExpr::When { subject, clauses, .. } => {
                // Check the subject expression
                if self.check_expression_for_duplicate_inputs(subject) {
                    return true;
                }
                
                // Check each clause
                for clause in clauses {
                    // Check the guard if present
                    if let Some(guard) = &clause.guard {
                        if self.check_guard_for_duplicate_inputs(guard) {
                            return true;
                        }
                    }
                    
                    // Check the then expression
                    if self.check_expression_for_duplicate_inputs(&clause.then) {
                        return true;
                    }
                }
                
                false
            },
            
            // Add more expression types as needed
            _ => false,
        }
    }
    
    // Check if a function call is related to duplicate input checking
    fn is_duplicate_check_call(&self, fun: &TypedExpr, args: &[aiken_lang::ast::CallArg<TypedExpr>]) -> bool {
        // Look for list module functions that are commonly used for checking duplicates
        if let TypedExpr::ModuleSelect { module_name, label, .. } = fun {
            if module_name == "list" {
                match label.as_str() {
                    "find" | "count" | "index_of" => {
                        println!("Found list.{} operation - potential duplicate check", label);
                        
                        // Check if the predicate is comparing addresses
                        if args.len() >= 2 {
                            // For list functions, the second argument is usually the predicate
                            return self.contains_address_check(&args[1].value);
                        }
                    },
                    _ => {}
                }
            }
        }
        
        // Also check RecordAccess for list.find etc. pattern
        if let TypedExpr::RecordAccess { label, record, .. } = fun {
            if let TypedExpr::Var { name, .. } = &**record {
                if name == "list" {
                    match label.as_str() {
                        "find" | "count" | "index_of" => {
                            println!("Found list.{} operation - potential duplicate check", label);
                            
                            // Check if the predicate is comparing addresses
                            if args.len() >= 2 {
                                return self.contains_address_check(&args[1].value);
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
        
        false
    }
    
    // Check if a binary operation is comparing addresses
    fn is_address_comparison(&self, op: &aiken_lang::ast::BinOp, left: &TypedExpr, right: &TypedExpr) -> bool {
        match op {
            aiken_lang::ast::BinOp::Eq | aiken_lang::ast::BinOp::NotEq => {
                self.is_address_access(left) || self.is_address_access(right)
            },
            _ => false
        }
    }
    
    // Check if an expression is accessing an address field
    fn is_address_access(&self, expr: &TypedExpr) -> bool {
        match expr {
            TypedExpr::RecordAccess { label, .. } => {
                label.contains("address") || label.contains("addr")
            },
            _ => false
        }
    }
    
    // Check if an expression contains address comparisons
    fn contains_address_check(&self, expr: &TypedExpr) -> bool {
        match expr {
            TypedExpr::Fn { body, .. } => {
                // Check the function body for address comparisons
                self.check_expression_for_duplicate_inputs(body)
            },
            _ => false
        }
    }
    
    // Analyze clause guards in when expressions
    fn check_guard_for_duplicate_inputs(&self, guard: &aiken_lang::ast::TypedClauseGuard) -> bool {
        match guard {
            aiken_lang::ast::ClauseGuard::Equals { left, right, .. } => {
                self.check_guard_for_duplicate_inputs(left) || 
                self.check_guard_for_duplicate_inputs(right)
            },
            aiken_lang::ast::ClauseGuard::NotEquals { left, right, .. } => {
                self.check_guard_for_duplicate_inputs(left) || 
                self.check_guard_for_duplicate_inputs(right)
            },
            aiken_lang::ast::ClauseGuard::And { left, right, .. } => {
                self.check_guard_for_duplicate_inputs(left) || 
                self.check_guard_for_duplicate_inputs(right)
            },
            aiken_lang::ast::ClauseGuard::Or { left, right, .. } => {
                self.check_guard_for_duplicate_inputs(left) || 
                self.check_guard_for_duplicate_inputs(right)
            },
            _ => false,
        }
    }

    // Helper function to get indentation based on nesting level
    fn indent(&self, level: u8) -> String {
        "  ".repeat(level as usize)
    }

    // Perform symbolic execution on an expression
    fn execute_expression(&self, expr: &TypedExpr, env: &mut SymbolicEnvironment) -> ExprResult {
        // Get current function level from the environment
        let current_level = env.function_level.unwrap_or(0);
        let indent = self.indent(current_level);
        
        match expr {
            TypedExpr::Var { name, .. } => {
                // Look up variable in environment
                println!("DEBUG: Executing expression type Var on: {}", name);
                if let Some(value) = env.variables.get(name) {
                    let mut uses = HashSet::new();
                    let uses_purpose = value.origin == ValueOrigin::Purpose;
                    let uses_inputs = value.origin == ValueOrigin::TransactionInputs;
                    uses.insert(value.origin.clone());
                    ExprResult {
                        value: value.clone(),
                        environment: env.clone(),
                        findings: Vec::new(),
                        uses,
                        uses_purpose,
                        uses_inputs,
                        location: Some(expr.location()),
                        function_level: 0,
                    }
                } else {
                    // Variable not found, create unknown value
                    ExprResult {
                        value: SymbolicValue::unknown(expr.tipo()),
                        environment: env.clone(),
                        findings: Vec::new(),
                        uses: HashSet::new(),
                        uses_purpose: false,
                        uses_inputs: false,
                        location: Some(expr.location()),
                        function_level: 0,
                    }
                }
            },
            TypedExpr::RecordAccess { label, record, .. } => {
                println!("DEBUG: Expression type RecordAccess on: {}", label);
                // Execute the record expression first
                let record_result = self.execute_expression(record, env);
                let mut new_env = record_result.environment;
                
                // Get the value of the record
                let record_value = record_result.value;
                
                // Track if we're accessing purpose or inputs directly
                let mut uses_purpose = record_result.uses_purpose;
                let mut uses_inputs = record_result.uses_inputs;
                
                // Handle special cases for ScriptContext paths
                let origin = match &record_value.origin {
                    ValueOrigin::ScriptContext => {
                        // Direct field access on ScriptContext
                        match label.as_str() {
                            "transaction" => ValueOrigin::Transaction,
                            "purpose" => {
                                uses_purpose = true;
                                ValueOrigin::Purpose
                            },
                            _ => ValueOrigin::Other(format!("ScriptContext.{}", label)),
                        }
                    },
                    
                    ValueOrigin::Transaction => {
                        // Field access on Transaction
                        match label.as_str() {
                            "inputs" => {
                                uses_inputs = true;
                                ValueOrigin::TransactionInputs
                            },
                            _ => ValueOrigin::Other(format!("Transaction.{}", label)),
                        }
                    },
                    
                    ValueOrigin::Purpose => {
                        // Field access on Purpose - looking for OutputReference in Spend
                        match label.as_str() {
                            "output_reference" => ValueOrigin::OutputReference,
                            _ => ValueOrigin::Other(format!("Purpose.{}", label)),
                        }
                    },
                    
                    ValueOrigin::InputToken => {
                        // Field access on InputToken - looking for OutputReference in Spend
                        match label.as_str() {
                            "output_reference" => ValueOrigin::OutputReference,
                            "output" => ValueOrigin::InputTokenOutput,
                            _ => ValueOrigin::Other(format!("InputToken.{}", label)),
                        }
                    },

                    ValueOrigin::InputTokenOutput => {
                        // Field access on InputTokenOutput - looking for OutputReference in Spend
                        match label.as_str() {
                            "address" => ValueOrigin::InputTokenAddress,
                            _ => ValueOrigin::Other(format!("InputTokenOutput.{}", label)),
                        }
                    },

                    _ => {
                        // Other field access, track derivation
                        ValueOrigin::Other(format!("{}", label.as_str()))
                    }
                };
                
                // Create the resulting value
                let result_value = SymbolicValue::derived(
                    origin,
                    expr.tipo(),
                    vec![record_value.origin.clone()]
                );
                let mut uses = record_result.uses.clone();
                uses.insert(result_value.origin.clone());
                ExprResult {
                    value: result_value,
                    environment: new_env,
                    findings: record_result.findings,
                    uses,
                    uses_purpose,
                    uses_inputs,
                    location: Some(expr.location()),
                    function_level: record_result.function_level,
                }
            },
            TypedExpr::Assignment { kind, pattern, value, .. } => {
                // Execute the value expression
                let value_result = self.execute_expression(value, env);
                println!("DEBUG: Value Result at assignment: {}", value_result.value);
                let mut new_env = value_result.environment.clone();
                let mut uses_purpose = value_result.uses_purpose;
                let mut uses_inputs = value_result.uses_inputs;
                let current_level = env.function_level.unwrap_or(0);
                let indent = self.indent(current_level);
                
                match kind {
                    AssignmentKind::Let => {
                        // Process Let assignments
                        match pattern {
                            // Case 1: Simple variable assignment (let pps = expression)
                            aiken_lang::ast::Pattern::Var { name, .. } => {
                                println!("{}[Level {}] Assignment to variable: {}", indent, current_level, name);
                                
                                // General case: Propagate symbolic information from value_result to the variable
                                // This ensures that if a function call returns a value with special meaning,
                                // the variable holding it will carry that meaning
                                if value_result.value.origin != ValueOrigin::Unknown || !value_result.value.derived_from.is_empty() {
                                    println!("{}[Level {}] Propagating symbolic value from expression to variable: {}", 
                                             indent, current_level, name);
                                    println!("{}[Level {}]   Origin: {:?}", indent, current_level, value_result.value.origin);
                                    
                                    if !value_result.value.derived_from.is_empty() {
                                        let derived_str = value_result.value.derived_from.iter()
                                            .map(|o| format!("{:?}", o))
                                            .collect::<Vec<_>>()
                                            .join(", ");
                                        println!("{}[Level {}]   Derived from: {}", indent, current_level, derived_str);
                                    }
                                    
                                    // Register variable with the symbolic value from the expression result
                                    new_env.add_variable(name.clone(), value_result.value.clone());
                                } else {
                                    println!("{}[Level {}] No symbolic value to propagate", 
                                             indent, current_level);
                                    println!("DEBUG: Value Result: {:}", value_result.value);

                                }
                            },
                            // Case 2: Destructuring pattern (let ScriptContext { purpose } = ctx)
                            aiken_lang::ast::Pattern::Constructor { name: constructor_name, arguments, .. } => {
                                // Handle ScriptContext destructuring
                                if constructor_name == "ScriptContext" {
                                    // Check if the value is our script context variable
                                    if value_result.value.origin == ValueOrigin::ScriptContext {
                                        for arg in arguments {
                                            if let Some(label) = &arg.label {
                                                if label == "purpose" {
                                                    if let aiken_lang::ast::Pattern::Var { name: purpose_var, .. } = &arg.value {
                                                        println!("{}[Level {}] FOUND: Destructured purpose from ScriptContext to: {}", 
                                                                 indent, current_level, purpose_var);
                                                        
                                                        // For pattern types, use the value's type
                                                        let purpose_type = value.tipo();
                                                        
                                                        // Create a purpose value
                                                        let purpose_value = SymbolicValue::derived(
                                                            ValueOrigin::Purpose,
                                                            purpose_type,
                                                            vec![ValueOrigin::ScriptContext]
                                                        );
                                                        // Register the variable as holding ScriptContext.purpose
                                                        new_env.add_variable(purpose_var.clone(), purpose_value);
                                                    }
                                                }
                                                
                                                // Look for 'transaction' in arguments
                                                if label == "transaction" {
                                                    if let aiken_lang::ast::Pattern::Var { name: transaction_var, .. } = &arg.value {
                                                        println!("{}[Level {}] FOUND: Destructured transaction from ScriptContext to: {}", 
                                                                 indent, current_level, transaction_var);
                                                        
                                                        // For pattern types, use the value's type
                                                        let transaction_type = value.tipo();
                                                        
                                                        // Create a transaction value
                                                        let transaction_value = SymbolicValue::derived(
                                                            ValueOrigin::Transaction,
                                                            transaction_type,
                                                            vec![ValueOrigin::ScriptContext]
                                                        );
                                                        // Register the variable as holding ScriptContext.transaction
                                                        new_env.add_variable(transaction_var.clone(), transaction_value);
                                                    }
                                                }
                                            }
                                        }
                                    }else{
                                        println!("ERROR: Expected right hand side to be ScriptContext, but got {}", value_result.value);
                                    }
                                } else if constructor_name == "Transaction" {
                                    // Check if the value is our transaction variable
                                    if value_result.value.origin == ValueOrigin::Transaction {
                                        for arg in arguments {
                                            if let Some(label) = &arg.label {
                                                if label == "inputs" {
                                                    if let aiken_lang::ast::Pattern::Var { name: inputs_var, .. } = &arg.value {
                                                        println!("{}[Level {}] FOUND: Destructured inputs from Transaction to: {}", 
                                                                 indent, current_level, inputs_var);
                                                        
                                                        // For pattern types, use the value's type
                                                        let inputs_type = value.tipo();
                                                        
                                                        // Create a purpose value
                                                        let inputs_value = SymbolicValue::derived(
                                                            ValueOrigin::TransactionInputs,
                                                            inputs_type,
                                                            vec![ValueOrigin::ScriptContext,ValueOrigin::Transaction]
                                                        );
                                                        // Register the variable as holding ScriptContext.purpose
                                                        new_env.add_variable(inputs_var.clone(), inputs_value);
                                                    }
                                                }
                                            }
                                        }
                                    }else{
                                        println!("ERROR: Expected right hand side to be Transaction, but got {}", value_result.value);
                                    }
                                } else if constructor_name == "Input"{
                                    if value_result.value.origin == ValueOrigin::InputToken {
                                        for arg in arguments {
                                            if let Some(label) = &arg.label {
                                                if label == "output_reference" {
                                                    if let aiken_lang::ast::Pattern::Var { name: output_reference_var, .. } = &arg.value {
                                                        println!("{}[Level {}] FOUND: Destructured output_reference from InputToken to: {}", 
                                                                 indent, current_level, output_reference_var);
                                                        let output_reference_type = value.tipo();
                                                        let output_reference_value = SymbolicValue::derived(
                                                            ValueOrigin::OutputReference,
                                                            output_reference_type,
                                                            vec![ValueOrigin::ScriptContext,ValueOrigin::Transaction,ValueOrigin::InputToken]
                                                        );
                                                        new_env.add_variable(output_reference_var.clone(), output_reference_value);
                                                    }
                                                }
                                                if label == "output" {
                                                    if let aiken_lang::ast::Pattern::Var { name: output_var, .. } = &arg.value {
                                                        println!("{}[Level {}] FOUND: Destructured output from InputToken to: {}", 
                                                                 indent, current_level, output_var);
                                                        let output_type = value.tipo();
                                                        let output_value = SymbolicValue::derived(
                                                            ValueOrigin::InputTokenOutput,
                                                            output_type,
                                                            vec![ValueOrigin::ScriptContext,ValueOrigin::Transaction,ValueOrigin::InputToken]
                                                        );
                                                        new_env.add_variable(output_var.clone(), output_value); 
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        println!("ERROR: Expected right hand side to be InputToken, but got {}", value_result.value);
                                    }
                                } else if constructor_name == "Output"{
                                    if value_result.value.origin == ValueOrigin::InputTokenOutput {
                                        for arg in arguments {
                                            if let Some(label) = &arg.label {
                                                if label == "address" {
                                                    if let aiken_lang::ast::Pattern::Var { name: address_var, .. } = &arg.value {
                                                        println!("{}[Level {}] FOUND: Destructured address from InputTokenOutput to: {}", 
                                                                 indent, current_level, address_var);
                                                        let address_type = value.tipo();    
                                                        let address_value = SymbolicValue::derived(
                                                            ValueOrigin::InputTokenAddress,
                                                            address_type,
                                                            vec![ValueOrigin::ScriptContext,ValueOrigin::Transaction,ValueOrigin::InputToken,ValueOrigin::InputTokenOutput]
                                                        );
                                                        new_env.add_variable(address_var.clone(), address_value);
                                                    }
                                                }
                                            }
                                        }
                                    }else{
                                        println!("ERROR: Expected right hand side to be InputTokenOutput, but got {}", value_result.value);
                                    }
                                } else {
                                    println!("DEBUG: Destructuring only implemented for ScriptContext or Transaction, but got {}", value_result.value);
                                }
                            },
                            // We don't need to handle other pattern types for this specific analysis
                            _ => {
                                println!("DEBUG: Other pattern types, apart from variable and destructuring, not implemented for assignment:");
                            }
                        }
                    },
                    AssignmentKind::Expect => {
                        println!("DEBUG: Expect assignment");
                        match pattern {
                            aiken_lang::ast::Pattern::Constructor { name: constructor_name, arguments, .. } => {
                                println!("DEBUG: Expect assignment constructor: {}", constructor_name);
                                if constructor_name == "Spend" {
                                    println!("{}[Level {}] Found pattern match: expect Spend(...) = ...", 
                                            indent, current_level);
                                    
                                    // First check if the right-hand side is purpose
                                    let is_purpose = value_result.value.origin == ValueOrigin::Purpose;
                                    
                                    if is_purpose {
                                        // Extract variable names from the arguments
                                        for (index, arg) in arguments.iter().enumerate() {
                                            if let aiken_lang::ast::Pattern::Var { name: var_name, .. } = &arg.value {
                                                println!("{}[Level {}] FOUND: Spend pattern extracted variable: {}",
                                                        indent, current_level, var_name);
                                                
                                                // Create a new symbolic value for the output reference
                                                // Fix: Get the type properly from the expression
                                                let arg_type = expr.tipo();
                                                
                                                let oref_value = SymbolicValue::derived(
                                                    ValueOrigin::OutputReference,
                                                    arg_type,
                                                    vec![ValueOrigin::Purpose]
                                                );
                                                
                                                // Register the variable in the environment
                                                new_env.add_variable(var_name.clone(), oref_value);
                                            }
                                        }
                                        
                                        // Add an assertion condition that the purpose is Spend
                                        new_env.add_condition(SymbolicCondition::Assertion {
                                            condition: Box::new(SymbolicCondition::Custom {
                                                description: "Purpose is Spend".to_string(),
                                                relates_to_inputs: false,
                                                relates_to_output_ref: true,
                                                location: expr.location(),
                                            }),
                                            location: expr.location(),
                                        });
                                        
                                        // This is a case where we're using purpose
                                        uses_purpose = true;
                                    }
                                }
                                // Detect the pattern: expect Some(found_input) = <expression using inputs and output_reference>
                                else if constructor_name == "Some" && arguments.len() == 1 {
                                    println!("{}[Level {}] Found potential pattern match: expect Some(...) = ...", 
                                            indent, current_level);
                                    
                                    // Extract the variable name that will store the found input
                                    let found_input_var = if let aiken_lang::ast::Pattern::Var { name, .. } = &arguments[0].value {
                                        Some(name.clone())
                                    } else {
                                        None
                                    };
                                    
                                    // Check if the right side uses both transaction inputs and output_reference
                                    if value_result.value.origin == ValueOrigin::InputToken {
                                        println!("{}[Level {}] FOUND: Self input token discovery detected", 
                                                indent, current_level);
                                        
                                        // If we found the variable name, register it as derived from inputs and output ref
                                        if let Some(var_name) = found_input_var {
                                            // Create a symbolic value representing the found input
                                            let found_input_value = SymbolicValue::derived(
                                                ValueOrigin::InputToken,
                                                expr.tipo(),
                                                vec![ValueOrigin::TransactionInputs, ValueOrigin::OutputReference]
                                            );
                                            println!("DEBUG: Value Result: {:}", value_result.value);
                                            
                                            // Register in environment
                                            new_env.add_variable(var_name.clone(), found_input_value);
                                            
                                            // Add a condition that we're checking output references match
                                            new_env.add_condition(SymbolicCondition::Custom {
                                                description: "Output reference validation pattern detected".to_string(),
                                                relates_to_inputs: true,
                                                relates_to_output_ref: true,
                                                location: expr.location(),
                                            });
                                            
                                            // This uses both purpose (for output_reference) and inputs
                                            uses_purpose = true;
                                            uses_inputs = true;
                                            
                                            println!("{}[Level {}] Registered variable '{}' as carrying input UTXO value", 
                                                    indent, current_level, var_name);
                                        }
                                    } else {
                                        println!("Some constructor is expected only for input token discovery, but right hand side is {}", value_result.value);
                                    }
                                }
                            },
                            aiken_lang::ast::Pattern::Var { name, .. } => {
                                println!("{}[Level {}] Assignment to variable: {}", indent, current_level, name);
                                
                                // General case: Propagate symbolic information from value_result to the variable
                                // This ensures that if a function call returns a value with special meaning,
                                // the variable holding it will carry that meaning
                                if value_result.value.origin != ValueOrigin::Unknown || !value_result.value.derived_from.is_empty() {
                                    println!("{}[Level {}] Propagating symbolic value from expression to variable: {}", 
                                             indent, current_level, name);
                                    println!("{}[Level {}]   Origin: {:?}", indent, current_level, value_result.value.origin);
                                    
                                    if !value_result.value.derived_from.is_empty() {
                                        let derived_str = value_result.value.derived_from.iter()
                                            .map(|o| format!("{:?}", o))
                                            .collect::<Vec<_>>()
                                            .join(", ");
                                        println!("{}[Level {}]   Derived from: {}", indent, current_level, derived_str);
                                    }
                                    
                                    // Register variable with the symbolic value from the expression result
                                    new_env.add_variable(name.clone(), value_result.value.clone());
                                } else {
                                    println!("{}[Level {}] No symbolic value to propagate", 
                                             indent, current_level);
                                    println!("DEBUG: Value Result: {:}", value_result.value);

                                }
                            },
                            _ => {
                                println!("DEBUG: Except assignment only implemented for Constructor and Variable patterns");
                            }
                        }
                    }
                }
                
                // Return the ExprResult after processing all patterns
                ExprResult {
                    value: value_result.value,
                    environment: new_env,
                    findings: value_result.findings,
                    uses: value_result.uses.clone(),
                    uses_purpose,
                    uses_inputs,
                    location: Some(expr.location()),
                    function_level: value_result.function_level,
                }
            },
            TypedExpr::Call { fun, args, .. } => {
                // Process function expression first
                let mut current_env = env.clone();
                let mut all_findings = Vec::new();
                let mut uses_purpose = false;
                let mut uses_inputs = false;
                let mut uses = HashSet::new();
                
                // Process function expression
                let fun_result = self.execute_expression(fun, &mut current_env);
                current_env = fun_result.environment.clone(); // Clone to avoid partial move
                all_findings.extend(fun_result.findings.clone());
                uses_purpose |= fun_result.uses_purpose;
                uses_inputs |= fun_result.uses_inputs;
                uses.extend(fun_result.uses.clone());
                // Get function name for debugging
                let function_name = match &**fun {
                    TypedExpr::Var { name, .. } => name.clone(),
                    TypedExpr::ModuleSelect { module_name, label, .. } => format!("{}::{}", module_name, label),
                    _ => "anonymous function".to_string()
                };
                println!("{}Calling Function name: {}", indent, function_name);
                // Check if this is from aiken/list module
                let is_list_module_function = match &**fun {
                    // Handle module-select expressions like module.function
                    TypedExpr::ModuleSelect { module_name, label, .. } => {
                        module_name == "aiken/list"
                    }
                    // For other expression types, we don't inline
                    _ => false
                };
                
                // Get function location
                let location_str = {
                    let loc = expr.location();
                    format!("at line {}", loc.start)
                };
                
                // Only print debug info for list module functions
                if is_list_module_function {
                    println!("{}[Level {}] CALL: aiken/list function {} {} with {} arguments", 
                             indent, current_level, function_name, location_str, args.len());
                }
                
                // Process arguments
                let mut arg_results = Vec::new();
                for (i, arg) in args.iter().enumerate() {
                    // Only print debug info for list module functions
                    if is_list_module_function {
                        println!("{}[Level {}] ARG #{}", indent, current_level, i+1);
                    }
                    let arg_result = self.execute_expression(&arg.value, &mut current_env);
                    current_env = arg_result.environment.clone(); // Clone to avoid partial move
                    all_findings.extend(arg_result.findings.clone());
                    uses_purpose |= arg_result.uses_purpose;
                    uses_inputs |= arg_result.uses_inputs;
                    arg_results.push(arg_result.clone());
                    uses.extend(arg_result.uses.clone());
                }
                
                // Check if we should inline this function call (only if at level 0)
                if fun_result.function_level == 0 {
                    // Try to find the function definition
                    if is_list_module_function {
                        // Only print debug for list module functions
                        println!("{}Found a list function call, with name {}", indent, function_name);
                        if function_name == "aiken/list::find" {
                            println!("{}Evaluating arguments for list.find", indent);
                            let list_result = arg_results[0].clone();
                            let predicate_result = arg_results[1].clone();
                            let is_list_inputs = list_result.value.origin == ValueOrigin::TransactionInputs;
                            let does_predicate_use_output_ref = predicate_result.uses.contains(&ValueOrigin::OutputReference);
                            let mut val_origin = ValueOrigin::Unknown;
                            println!("{}is_list_inputs: {}", indent, is_list_inputs);
                            println!("{}does_predicate_use_output_ref: {}", indent, does_predicate_use_output_ref);
                            if is_list_inputs && does_predicate_use_output_ref {
                                val_origin = ValueOrigin::InputToken;
                            } else if is_list_inputs {
                                val_origin = ValueOrigin::Unknown;
                            }
                            let val_value = SymbolicValue::derived(val_origin, expr.tipo(), vec![]);
                            let result = ExprResult {
                                value: val_value,
                                environment: current_env,
                                findings: all_findings,
                                uses,
                                uses_purpose,
                                uses_inputs,
                                location: Some(expr.location()),
                                function_level: fun_result.function_level,
                            };
                            return result;
                        } else if function_name == "aiken/list::map" {
                            println!("{}Evaluating arguments for list.map", indent);
                            let list_result = arg_results[0].clone();
                            let predicate_result = arg_results[1].clone();
                            let is_list_inputs = list_result.value.origin == ValueOrigin::TransactionInputs;
                            let is_list_outputs = list_result.value.origin == ValueOrigin::InputTokenOutput;
                            let does_predicate_use_output = predicate_result.uses.contains(&ValueOrigin::InputTokenOutput);
                            let does_predicate_use_address = predicate_result.uses.contains(&ValueOrigin::InputTokenAddress);
                            println!("DEBUG: List.Map {}Value of list: {:#?}", indent, list_result.value);
                            println!("DEBUG: List.Map {}Value of predicate: {:#?}", indent, predicate_result.value);
                            println!("DEBUG: List.Map {}does_predicate_use_address: {}", indent, does_predicate_use_address);
                            let mut val_origin = ValueOrigin::Unknown;
                            if is_list_inputs && does_predicate_use_address {
                                val_origin = ValueOrigin::InputTokenAddress;
                            } else if is_list_inputs && does_predicate_use_output {
                                val_origin = ValueOrigin::InputTokenOutput;
                            } else if is_list_inputs {
                                match predicate_result.value.origin {
                                    ValueOrigin::Other(s) => {
                                        if s == "address"{
                                            val_origin = ValueOrigin::InputTokenAddress;
                                        } else if s == "output_reference"{
                                            val_origin = ValueOrigin::OutputReference;
                                        } else if s == "output"{
                                            val_origin = ValueOrigin::InputTokenOutput;
                                        } else if s == "inputs"{
                                            val_origin = ValueOrigin::TransactionInputs;
                                        }
                                    }
                                    _ => val_origin = val_origin,
                                }
                            } else if is_list_outputs {
                                match predicate_result.value.origin {
                                    ValueOrigin::Other(s) => {
                                        if s == "address"{
                                            val_origin = ValueOrigin::InputTokenAddress;
                                        }
                                    },
                                    _ => val_origin = val_origin,
                                }
                            }
                            let val_value = SymbolicValue::derived(val_origin, expr.tipo(), vec![]);
                            let result = ExprResult {
                                value: val_value,
                                environment: current_env,
                                findings: all_findings,
                                uses,
                                uses_purpose,
                                uses_inputs,
                                location: Some(expr.location()),
                                function_level: fun_result.function_level,
                            };
                            return result;
                        } else if function_name == "aiken/list::count" {
                            println!("{}Evaluating arguments for list.count", indent);
                            let list_result = arg_results[0].clone();
                            let predicate_result = arg_results[1].clone();
                            let is_list_inputs = list_result.value.origin == ValueOrigin::TransactionInputs;
                            let is_list_outputs = list_result.value.origin == ValueOrigin::InputTokenOutput;
                            let is_list_addresses = list_result.value.origin == ValueOrigin::InputTokenAddress;
                            let does_predicate_use_address = predicate_result.uses.contains(&ValueOrigin::InputTokenAddress);
                            let mut val_origin = ValueOrigin::Unknown;
                            if is_list_inputs && does_predicate_use_address {
                                val_origin = ValueOrigin::TokenCount;
                            } else {
                                match predicate_result.value.origin {
                                    ValueOrigin::Other(s) => {
                                        if s == "address"{
                                            val_origin = ValueOrigin::TokenCount;
                                        }
                                    }
                                    _ => val_origin = val_origin,
                                }
                            }
                            let val_value = SymbolicValue::derived(val_origin, expr.tipo(), vec![]);
                            let result = ExprResult {
                                value: val_value,
                                environment: current_env,
                                findings: all_findings,
                                uses,
                                uses_purpose,
                                uses_inputs,
                                location: Some(expr.location()),
                                function_level: fun_result.function_level,
                            };
                            return result;
                        }
                    }else if let Some(function_info) = self.find_function_to_inline(fun) {
                        println!("\n{}>>> INLINING FUNCTION: {} <<<", indent, function_info.qualified_name);
                        println!("{}Call site: {}", indent, location_str);
                        
                        // Create a new environment with mapped arguments
                        let mut function_env = current_env.clone();
                        
                        // Set function level in the environment for the inlined function
                        function_env.function_level = Some(current_level + 1);
                        
                        // Map arguments from the call to function parameters
                        let mapped_successfully = self.map_function_arguments(
                            &function_info,
                            args,
                            &mut function_env,
                            &arg_results,
                            current_level + 1
                        );
                        
                        if mapped_successfully {
                            println!("{}Arguments successfully mapped to parameters", indent);
                            
                            // Execute the function body with the new environment
                            println!("{}BEGIN INLINED FUNCTION EXECUTION...", indent);
                            println!("{}----------------------------------------", indent);
                            let mut body_result = self.execute_expression(&function_info.body, &mut function_env);
                            println!("{}----------------------------------------", indent);
                            println!("{}END INLINED FUNCTION EXECUTION", indent);
                            
                            // Increase function level to indicate we're in a function call
                            body_result.function_level = fun_result.function_level + 1;
                            
                            // Merge findings and tracking flags
                            all_findings.extend(body_result.findings.clone());
                            uses_purpose |= body_result.uses_purpose;
                            uses_inputs |= body_result.uses_inputs;
                            
                            if body_result.uses_purpose {
                                println!("{}Function uses purpose: YES", indent);
                            }
                            if body_result.uses_inputs {
                                println!("{}Function uses inputs: YES", indent);
                            }
                            // Use the result value from the function body
                            let result = ExprResult {
                                value: body_result.value,
                                environment: current_env, // Keep the caller's environment
                                findings: all_findings,
                                uses: body_result.uses.clone(),
                                uses_purpose,
                                uses_inputs,
                                location: Some(expr.location()),
                                function_level: fun_result.function_level,
                            };
                            // environment.function_returns.insert(function_name, result.value);
                            return result;
                        } else if is_list_module_function {
                            // Only print debug for list module functions
                            println!("{}aiken/list function cannot be inlined", indent);
                        }
                    }
                } else {
                    // Not inlining anymore, detect usage only through arguments
                    println!("{}Function call detected, but not inlining because we're at level 2", indent);
                }
                
                ExprResult {
                    value: SymbolicValue::unknown(expr.tipo()),
                    environment: current_env,
                    findings: all_findings,
                    uses,
                    uses_purpose,
                    uses_inputs,
                    location: Some(expr.location()),
                    function_level: fun_result.function_level,
                }
            },
            TypedExpr::Fn { body, .. } => {
                let body_result = self.execute_expression(body, env);
                let mut uses = body_result.uses.clone();
                ExprResult {
                    value: body_result.value,
                    environment: env.clone(),
                    findings: body_result.findings,
                    uses,
                    uses_purpose: body_result.uses_purpose,
                    uses_inputs: body_result.uses_inputs,
                    location: Some(expr.location()),
                    function_level: body_result.function_level,
                }
            },
            TypedExpr::BinOp { name, left, right, .. } => {
                let left_result = self.execute_expression(left, env);
                let right_result = self.execute_expression(right, env);
                let mut new_env = right_result.environment;
                
                // Combine findings and uses from both sides
                let mut findings = Vec::new();
                findings.extend(left_result.findings);
                findings.extend(right_result.findings);
                
                let mut uses = left_result.uses.clone();
                uses.extend(right_result.uses);
                
                // Create a symbolic value for the result
                let value = right_result.value.clone();

                // Log special cases
                if matches!(name, 
                    BinOp::Eq | BinOp::NotEq | BinOp::LtInt | 
                    BinOp::LtEqInt | BinOp::GtEqInt | BinOp::GtInt) {
                    let left_val = left_result.value.origin;
                    let right_val = right_result.value.origin;
                    let is_left_token_count = left_val == ValueOrigin::TokenCount;
                    let is_right_token_count = right_val == ValueOrigin::TokenCount;
                    if is_left_token_count || is_right_token_count {
                        println!("DEBUG: Token count comparison detected with operator {:?}", name);
                        findings.push(SecurityFinding{
                            description: "Token count comparison detected".to_string(),
                            location: expr.location(),
                            kind: SecurityPatternKind::InputTokenCountComparison,
                            confidence: 80,
                        });
                    }
                }
                
                ExprResult {
                    value,
                    environment: new_env,
                    findings,
                    uses,
                    uses_purpose: left_result.uses_purpose || right_result.uses_purpose,
                    uses_inputs: left_result.uses_inputs || right_result.uses_inputs,
                    location: Some(expr.location()),
                    function_level: left_result.function_level,
                }
            },
            TypedExpr::When { subject, clauses, .. } => {
                println!("{}[Level {}] Executing When expression", indent, current_level);
                
                // First, evaluate the subject expression
                let subject_result = self.execute_expression(subject, env);
                let mut new_env = subject_result.environment;
                let mut all_findings = subject_result.findings;
                let mut uses_purpose = subject_result.uses_purpose;
                let mut uses_inputs = subject_result.uses_inputs;
                let mut uses = subject_result.uses.clone();
                // Track results from all clauses
                let mut clause_results = Vec::new();
                
                // Evaluate each clause's body
                // Note: We're simplifying here - in a real symbolic execution, we would
                // check which patterns match and only execute the matching clauses
                for clause in clauses {
                    println!("{}[Level {}] Executing clause", indent, current_level);
                    
                    // Clone the environment for this clause
                    let mut clause_env = new_env.clone();

                    // Check for "when purpose is { Spend(oref) => ... }" pattern
                    if subject_result.value.origin == ValueOrigin::Purpose {
                        println!("{}[Level {}] Found pattern match on Purpose", indent, current_level);
                        
                        if let aiken_lang::ast::Pattern::Constructor { name: constructor_name, arguments, .. } = &clause.pattern {
                            if constructor_name == "Spend" && arguments.len() == 1 {
                                println!("{}[Level {}] FOUND: when purpose is {{ Spend(oref) => ... }} pattern", indent, current_level);
                                
                                // Extract variable name for the output reference
                                if let aiken_lang::ast::Pattern::Var { name: var_name, .. } = &arguments[0].value {
                                    println!("{}[Level {}] Output reference bound to variable: {}", indent, current_level, var_name);
                                    
                                    // Create a symbolic value for the output reference
                                    let oref_value = SymbolicValue::derived(
                                        ValueOrigin::OutputReference,
                                        subject.tipo(),
                                        vec![ValueOrigin::Purpose]
                                    );
                                    
                                    // Register the variable in the environment for this clause
                                    clause_env.add_variable(var_name.clone(), oref_value);
                                    
                                    // Update tracking flags
                                    uses_purpose = true;
                                    
                                    // Add a condition that the purpose is Spend
                                    clause_env.add_condition(SymbolicCondition::Assertion {
                                        condition: Box::new(SymbolicCondition::Custom {
                                            description: "Purpose is Spend".to_string(),
                                            relates_to_inputs: false,
                                            relates_to_output_ref: true,
                                            location: clause.pattern.location(),
                                        }),
                                        location: clause.pattern.location(),
                                    });
                                }
                            }
                        }
                    }
                    
                    // If there's a guard, evaluate it
                    if let Some(guard) = &clause.guard {
                        println!("{}[Level {}] Evaluating clause guard", indent, current_level);
                        
                        // Check for duplicate input validation in the guard
                        if self.check_guard_for_duplicate_inputs(guard) {
                            println!("{}[Level {}] Found duplicate input check in When clause guard", indent, current_level);
                            all_findings.push(SecurityFinding {
                                kind: SecurityPatternKind::DuplicateInputCheck,
                                confidence: 90,
                                location: guard.location(),
                                description: "Duplicate input check found in When clause guard".to_string(),
                            });
                        }
                    }
                    
                    // Evaluate the clause body
                    let clause_result = self.execute_expression(&clause.then, &mut clause_env);
                    clause_results.push(clause_result.clone());
                    
                    // Merge flags and findings
                    all_findings.extend(clause_result.findings);
                    uses_purpose |= clause_result.uses_purpose;
                    uses_inputs |= clause_result.uses_inputs;
                    uses.extend(clause_result.uses.clone());
                }
                
                // Consolidate results: take the last successful clause result's value
                // In symbolic execution, we would merge the results with a more complex algorithm
                let value = if let Some(last_result) = clause_results.last() {
                    last_result.value.clone()
                } else {
                    // Default to subject's value if no clauses
                    subject_result.value.clone()
                };
                
                ExprResult {
                    value,
                    environment: new_env,
                    findings: all_findings,
                    uses,
                    uses_purpose,
                    uses_inputs,
                    location: Some(expr.location()),
                    function_level: subject_result.function_level,
                }
            },
            // For all other expression types, simplify by just traversing sub-expressions
            // without complex logic or condition tracking
            _ => {
                // Generic traversal of any sub-expressions
                let mut current_env = env.clone();
                let mut all_findings = Vec::new();
                let mut uses_purpose = false;
                let mut uses_inputs = false;
                let mut uses = HashSet::new();
                let mut child_results = Vec::new();
                let mut value = SymbolicValue::unknown(expr.tipo());
                
                // Use a helper to visit all child expressions
                for child in self.get_child_expressions(expr) {
                    let child_result = self.execute_expression(child, &mut current_env);
                    child_results.push(child_result.clone());
                    current_env = child_result.environment;
                    all_findings.extend(child_result.findings);
                    uses_purpose |= child_result.uses_purpose;
                    uses_inputs |= child_result.uses_inputs;
                    uses.extend(child_result.uses.clone());
                    value = child_result.value.clone();
                }
                
                return ExprResult {
                    value,
                    environment: current_env,
                    findings: all_findings,
                    uses,
                    uses_purpose,
                    uses_inputs,
                    location: Some(expr.location()),
                    function_level: 0,
                };
            }
        }
    }
    
    // Helper method to get child expressions for any expression type
    fn get_child_expressions<'a>(&self, expr: &'a TypedExpr) -> Vec<&'a TypedExpr> {
        let mut children = Vec::new();
        
        match expr {
            TypedExpr::BinOp { left, right, .. } => {
                children.push(&**left);
                children.push(&**right);
            },
            TypedExpr::UnOp { value, .. } => {
                children.push(&**value);
            },
            TypedExpr::If { branches, final_else, .. } => {
                for branch in branches {
                    children.push(&branch.condition);
                    children.push(&branch.body);
                }
                children.push(&**final_else);
            },
            TypedExpr::Sequence { expressions, .. } => {
                for expr in expressions {
                    children.push(expr);
                }
            },
            TypedExpr::Pipeline { expressions, .. } => {
                for expr in expressions {
                    children.push(expr);
                }
            },
            TypedExpr::List { elements, tail, .. } => {
                for elem in elements {
                    children.push(elem);
                }
                if let Some(t) = tail {
                    children.push(&**t);
                }
            },
            TypedExpr::Tuple { elems, .. } => {
                for elem in elems {
                    children.push(elem);
                }
            },
            TypedExpr::When { subject, clauses, .. } => {
                children.push(&**subject);
                for clause in clauses {
                    children.push(&clause.then);
                }
            },
            TypedExpr::RecordUpdate { spread, args, .. } => {
                children.push(&**spread);
                for arg in args {
                    children.push(&arg.value);
                }
            },
            TypedExpr::Fn { body, .. } => {
                children.push(&**body);
            },
            TypedExpr::Trace { text, then, .. } => {
                children.push(&**text);
                children.push(&**then);
            },
            TypedExpr::TupleIndex { tuple, .. } => {
                children.push(&**tuple);
            },
            TypedExpr::Call { fun, args, .. } => {
                children.push(&**fun);
                for arg in args {
                    children.push(&arg.value);
                }
            },
            TypedExpr::RecordAccess { record, .. } => {
                children.push(&**record);
            },
            // For other expression types that don't have child expressions
            _ => {}
        }
        
        children
    }

    // Extract the actual name from an ArgName debug representation
    fn extract_name_from_arg(&self, arg_name: &str) -> String {
        // Parse out just the name from the debug representation
        // Format is typically: Named { name: "ctx", label: "ctx", ... }
        if let Some(name_start) = arg_name.find("name: \"") {
            let name_start = name_start + 7; // Skip 'name: "'
            if let Some(name_end) = arg_name[name_start..].find('"') {
                return arg_name[name_start..(name_start + name_end)].to_string();
            }
        }
        // Fallback if we can't parse it
        arg_name.to_string()
    }

    // Find a function to inline
    fn find_function_to_inline(&self, fun: &TypedExpr) -> Option<&FunctionInfo> {
        // Check if this is the aiken/list module
        let is_list_module = match fun {
            TypedExpr::ModuleSelect { module_name, .. } => module_name == "list",
            _ => false
        };
        
        let indent = self.indent(0); // Always at level 0 when looking for functions to inline
        
        match fun {
            // If it's a variable, try to look it up in our function table
            TypedExpr::Var { name, .. } => {
                // Only print debug for relevant functions
                if is_list_module {
                    println!("{}[FIND] Looking for list function: {}", indent, name);
                }
                
                // Look for functions with this name
                // Since functions can share names across modules, look for all that match
                for (qualified_name, function_info) in &self.function_table {
                    if qualified_name.ends_with(&format!("::{}", name)) {
                        // Skip standard library functions (from aiken/ modules)
                        if function_info.module_name.starts_with("aiken/") {
                            // Only print debug for list module
                            if function_info.module_name == "aiken/list" {
                                println!("{}[FIND] List function {} found in standard library module {}, skipping inlining", 
                                        indent, name, function_info.module_name);
                            }
                            continue;
                        }
                        
                        // Found a non-standard library function - will be inlined
                        println!("{}[FIND] Found function to inline: {}", indent, qualified_name);
                        println!("{}[FIND] Function details:", indent);
                        println!("{}  - Module: {}", indent, function_info.module_name);
                        println!("{}  - Parameters: {}", indent, function_info.definition.arguments.len());
                        println!("{}  - Is validator: {}", indent, function_info.is_validator);
                        return Some(function_info);
                    }
                }
                
                // If not found in function table, look in the old functions map
                if self.functions.contains_key(name) {
                    // This is a legacy case - we don't have the full function info
                    if is_list_module {
                        println!("{}[FIND] List function found in legacy map but can't be inlined: {}", indent, name);
                    }
                }
                
                // Only print debug for list module
                if is_list_module {
                    println!("{}[FIND] No function definition found for list function: {}", indent, name);
                }
                None
            },
            
            // Handle module-select expressions like module.function
            TypedExpr::ModuleSelect { module_name, label, .. } => {
                let qualified_name = format!("{}::{}", module_name, label);
                
                // Only print for list module
                if module_name == "list" {
                    println!("{}[FIND] Looking for list module function: {}", indent, qualified_name);
                }
                
                // Skip standard library functions (from aiken/ modules)
                if module_name.starts_with("aiken/") {
                    // Only print for list module
                    if module_name == "aiken/list" {
                        println!("{}[FIND] List function found in standard library module {}, skipping inlining", 
                                 indent, module_name);
                    }
                    return None;
                }
                
                if let Some(function_info) = self.function_table.get(&qualified_name) {
                    // Found a non-standard library function - will be inlined
                    println!("{}[FIND] Found function to inline: {}", indent, qualified_name);
                    println!("{}[FIND] Function details:", indent);
                    println!("{}  - Module: {}", indent, function_info.module_name);
                    println!("{}  - Parameters: {}", indent, function_info.definition.arguments.len());
                    println!("{}  - Is validator: {}", indent, function_info.is_validator);
                    Some(function_info)
                } else {
                    // Not found
                    if module_name == "list" {
                        println!("{}[FIND] No function definition found for list module function: {}", 
                                 indent, qualified_name);
                    }
                    None
                }
            },
            
            // For other expression types, we don't inline
            _ => {
                // Only print for list module
                if is_list_module {
                    println!("{}[FIND] Cannot inline non-variable/non-module-select list function calls", indent);
                }
                None
            }
        }
    }

    // Map function arguments to function parameters
    fn map_function_arguments(
        &self,
        function_info: &FunctionInfo,
        args: &[aiken_lang::ast::CallArg<TypedExpr>],
        env: &mut SymbolicEnvironment,
        arg_results: &[ExprResult],
        level: u8
    ) -> bool {
        // Only print for functions being inlined (not aiken/ standard library)
        let is_std_lib = function_info.module_name.starts_with("aiken/");
        let is_list_module = function_info.module_name == "aiken/list";
        
        let indent = self.indent(level);
        
        // Parameter mapping always happens for functions being inlined
        // We only want to print details for list module or non-stdlib functions
        if !is_std_lib || is_list_module {
            println!("{}[Level {}] Mapping {} arguments to parameters", 
                     indent, level, args.len());
        }
        
        // Check if we have the right number of arguments
        if args.len() != function_info.definition.arguments.len() {
            // Only print errors for list module or non-stdlib functions
            if !is_std_lib || is_list_module {
                println!("{}[Level {}] ERROR: Argument count mismatch: {} arguments provided, {} parameters expected", 
                         indent, level, args.len(), function_info.definition.arguments.len());
            }
            return false;
        }
        
        // Only print header for list module or non-stdlib functions
        if !is_std_lib || is_list_module {
            println!("{}[Level {}] Parameter mapping:", indent, level);
        }
        
        // Map each argument to its parameter
        for (i, (_arg, arg_result)) in args.iter().zip(arg_results.iter()).enumerate() {
            let param = &function_info.definition.arguments[i];
            
            // Extract just the name from the debug representation
            let debug_name = format!("{:?}", param.arg_name);
            let param_name = self.extract_name_from_arg(&debug_name);
            
            // Only print details for list module or non-stdlib functions
            if !is_std_lib || is_list_module {
                println!("{}[Level {}]   {}: Argument {} -> Parameter {}", 
                         indent, level, i, 
                         debug_name, 
                         param_name);
            }
            
            // Add the parameter to the environment with the argument's value
            env.add_variable(param_name.clone(), arg_result.value.clone());
            
            // Propagate purpose and inputs tracking
            // Only print details for security-relevant tracking or non-stdlib functions
            if arg_result.value.origin != ValueOrigin::Unknown {
                if !is_std_lib || is_list_module {
                    println!("{}[Level {}]     (Argument arg_result.value.origin, propagating to parameter {})", 
                             indent, level, param_name);
                }
            }
            if arg_result.uses_inputs {
                if !is_std_lib || is_list_module {
                    println!("{}[Level {}]     (Argument uses inputs, propagating to parameter {})", 
                             indent, level, param_name);
                }
            }
        }
        
        // Only print success for list module or non-stdlib functions
        if !is_std_lib || is_list_module {
            println!("{}[Level {}] All arguments successfully mapped to parameters", indent, level);
        }
        true
    }

    // Check if a comparison involves output_reference and input.output_reference
    fn check_output_ref_comparison(
        &self, 
        left: &TypedExpr, 
        right: &TypedExpr, 
        env: &SymbolicEnvironment
    ) -> (bool, bool) {
        // Check if left side is output_reference
        let left_is_output_ref = self.is_output_reference_expr(left, env);
        
        // Check if right side is output_reference
        let right_is_output_ref = self.is_output_reference_expr(right, env);
        
        // Check if left side is input.output_reference
        let left_is_input_output_ref = self.is_input_output_reference_expr(left);
        
        // Check if right side is input.output_reference
        let right_is_input_output_ref = self.is_input_output_reference_expr(right);
        
        // We want one side to be output_reference and the other to be input.output_reference
        (
            left_is_output_ref && right_is_input_output_ref,
            right_is_output_ref && left_is_input_output_ref
        )
    }
    
    // Check if an expression refers to the output_reference from ScriptContext.purpose
    fn is_output_reference_expr(&self, expr: &TypedExpr, env: &SymbolicEnvironment) -> bool {
        match expr {
            // Case 1: Direct variable that holds output reference
            TypedExpr::Var { name, .. } => {
                if let Some(val) = env.variables.get(name) {
                    val.origin == ValueOrigin::OutputReference
                } else {
                    false
                }
            },
            
            // Case 2: Direct access to output_reference on purpose
            TypedExpr::RecordAccess { label, record, .. } => {
                if label == "output_reference" {
                    if let TypedExpr::Var { name, .. } = &**record {
                        if let Some(val) = env.variables.get(name) {
                            val.origin == ValueOrigin::Purpose
                        } else {
                            false
                        }
                    } else if let TypedExpr::RecordAccess { label: purpose_label, record: ctx_record, .. } = &**record {
                        if purpose_label == "purpose" {
                            if let TypedExpr::Var { name, .. } = &**ctx_record {
                                if let Some(script_ctx_name) = &env.script_context_name {
                                    name == script_ctx_name
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            
            // No other expressions are considered output_reference
            _ => false,
        }
    }
    
    // Check if an expression refers to input.output_reference (from the input parameter)
    fn is_input_output_reference_expr(&self, expr: &TypedExpr) -> bool {
        match expr {
            // Access to a field called output_reference
            TypedExpr::RecordAccess { label, record, .. } => {
                if label == "output_reference" {
                    // The record should be a parameter or variable from the lambda
                    if let TypedExpr::Var { .. } = &**record {
                        // This is a heuristic - we assume this is the input parameter
                        // In a more complete analysis, we'd track the lambda parameter
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            
            // No other expressions are considered input.output_reference
            _ => false,
        }
    }

    // Detect if an expression involves validating inputs against output references
    fn detect_input_output_ref_validation(
        &self,
        expr: &TypedExpr,
        env: &SymbolicEnvironment,
        indent: &str,
        level: u8
    ) -> bool {
        match expr {
            // For function calls, check if it operates on both inputs and output refs
            TypedExpr::Call { fun, args, .. } => {
                // First check if the arguments use inputs and/or output references
                let mut uses_inputs = false;
                let mut uses_output_ref = false;
                let mut arg_that_uses_inputs = None;
                let mut arg_that_uses_output_ref = None;
                
                // Check each argument
                for (i, arg) in args.iter().enumerate() {
                    let (arg_uses_inputs, arg_uses_output_ref) = 
                        self.check_expr_uses_inputs_and_oref(&arg.value, env);
                    
                    if arg_uses_inputs {
                        uses_inputs = true;
                        arg_that_uses_inputs = Some(i);
                    }
                    
                    if arg_uses_output_ref {
                        uses_output_ref = true;
                        arg_that_uses_output_ref = Some(i);
                    }
                    
                    // Also check for functions that might contain comparisons
                    if let TypedExpr::Fn { args: _fn_args, body, .. } = &arg.value {
                        let (body_uses_inputs, body_uses_output_ref) = 
                            self.check_expr_uses_inputs_and_oref(body, env);
                        
                        if body_uses_inputs {
                            uses_inputs = true;
                        }
                        
                        if body_uses_output_ref {
                            uses_output_ref = true;
                        }
                        
                        // Check specifically for equality comparison in the function body
                        if let TypedExpr::BinOp { name: op, left, right, .. } = &**body {
                            if op == &aiken_lang::ast::BinOp::Eq {
                                let (left_is_output_ref, right_is_output_ref) = 
                                    self.check_output_ref_comparison(&**left, &**right, env);
                                
                                if left_is_output_ref || right_is_output_ref {
                                    println!("{}[Level {}] FOUND: Function argument contains output_reference comparison", 
                                            indent, level);
                                    uses_output_ref = true;
                                    uses_inputs = true; // Assume the function is operating on inputs
                                }
                            }
                        }
                    }
                }
                
                // Check if the function itself is working with inputs or output refs
                let (fun_uses_inputs, fun_uses_output_ref) = 
                    self.check_expr_uses_inputs_and_oref(fun, env);
                
                if fun_uses_inputs {
                    uses_inputs = true;
                }
                
                if fun_uses_output_ref {
                    uses_output_ref = true;
                }
                
                // If this expression uses both inputs and output references, it might be validating
                if uses_inputs && uses_output_ref {
                    println!("{}[Level {}] FOUND: Expression uses both transaction inputs and output reference", 
                            indent, level);
                    
                    // Get function name for more context
                    let function_name = match &**fun {
                        TypedExpr::Var { name, .. } => name.clone(),
                        TypedExpr::ModuleSelect { module_name, label, .. } => format!("{}::{}", module_name, label),
                        _ => "anonymous function".to_string()
                    };
                    
                    println!("{}[Level {}] Function: {}", indent, level, function_name);
                    
                    // Report which arguments use inputs and output refs
                    if let Some(input_arg) = arg_that_uses_inputs {
                        println!("{}[Level {}] Argument {} uses inputs", indent, level, input_arg);
                    }
                    
                    if let Some(oref_arg) = arg_that_uses_output_ref {
                        println!("{}[Level {}] Argument {} uses output reference", indent, level, oref_arg);
                    }
                    
                    return true;
                }
                
                false
            },
            
            // For binary operations, check if they compare inputs and output refs
            TypedExpr::BinOp { name: op, left, right, .. } => {
                if op == &aiken_lang::ast::BinOp::Eq {
                    // Check for direct comparison between output ref and input
                    let (left_is_output_ref, right_is_output_ref) = 
                        self.check_output_ref_comparison(&**left, &**right, env);
                    
                    if left_is_output_ref || right_is_output_ref {
                        println!("{}[Level {}] FOUND: Direct comparison between output_reference and input", 
                                indent, level);
                        return true;
                    }
                }
                
                // Also check if the binary operation uses both values
                let (left_uses_inputs, left_uses_output_ref) = 
                    self.check_expr_uses_inputs_and_oref(left, env);
                
                let (right_uses_inputs, right_uses_output_ref) = 
                    self.check_expr_uses_inputs_and_oref(right, env);
                
                if (left_uses_inputs && right_uses_output_ref) || 
                   (left_uses_output_ref && right_uses_inputs) {
                    println!("{}[Level {}] FOUND: Binary operation with inputs and output reference", 
                            indent, level);
                    return true;
                }
                
                false
            },
            
            // Check for patterns in other expression types
            _ => false
        }
    }
    
    // Helper to check if an expression uses transaction inputs and/or output references
    fn check_expr_uses_inputs_and_oref(
        &self, 
        expr: &TypedExpr,
        env: &SymbolicEnvironment
    ) -> (bool, bool) {
        match expr {
            // Variables might directly hold these values
            TypedExpr::Var { name, .. } => {
                let uses_inputs = if let Some(val) = env.variables.get(name) {
                    val.origin == ValueOrigin::TransactionInputs || 
                    val.derived_from.contains(&ValueOrigin::TransactionInputs)
                } else {
                    false
                };
                
                let uses_output_ref = if let Some(val) = env.variables.get(name) {
                    val.origin == ValueOrigin::OutputReference || 
                    val.derived_from.contains(&ValueOrigin::OutputReference)
                } else {
                    false
                };
                
                (uses_inputs, uses_output_ref)
            },
            
            // Record access could access these values
            TypedExpr::RecordAccess { label, record, .. } => {
                // Check for input.output_reference pattern
                if label == "output_reference" {
                    if let TypedExpr::Var { .. } = &**record {
                        // Might be an input parameter in a function
                        return (true, true); // Assume it could be both
                    }
                }
                
                // Check if accessing a field on transaction inputs
                if let TypedExpr::Var { name, .. } = &**record {
                    if let Some(val) = env.variables.get(name) {
                        if val.origin == ValueOrigin::TransactionInputs {
                            return (true, false);
                        } else if val.origin == ValueOrigin::OutputReference {
                            return (false, true);
                        }
                    }
                }
                
                // Check the record expression recursively
                self.check_expr_uses_inputs_and_oref(record, env)
            },
            
            // For other expressions, check their sub-expressions
            _ => {
                let mut uses_inputs = false;
                let mut uses_output_ref = false;
                
                // Check all child expressions
                for child in self.get_child_expressions(expr) {
                    let (child_uses_inputs, child_uses_output_ref) = 
                        self.check_expr_uses_inputs_and_oref(child, env);
                    
                    uses_inputs |= child_uses_inputs;
                    uses_output_ref |= child_uses_output_ref;
                }
                
                (uses_inputs, uses_output_ref)
            }
        }
    }
}

pub fn exec(
    Args {
        directory,
        deny,
    }: Args,
) -> miette::Result<()> {
    let result = with_project(directory.as_deref(), deny, |project| {
        println!("Project loaded successfully.");
        
        // Create our analyzer
        let mut analyzer = AstAnalyzer::new();
        
        // Run the type checker to get typed ASTs
        project.check(false, None, false, false, Tracing::silent())?;
        
        // Access modules after type checking
        let modules = project.modules();
        println!("Found {} modules in the project", modules.len());
        
        // Process each module to find validators and functions
        for module in modules {
            // println!("Processing module: {}", module.name);
            
            // First collect all functions for later analysis
            for def in module.ast.definitions() {
                if let Definition::Fn(function) = def {
                    // Register function with its module for unique identification
                    analyzer.register_function_with_module(function, &module.name);
                }
            }
            
            // Then collect all validators
            if module.kind == ModuleKind::Validator {
                println!("Found validator module: {}", module.name);
                
                for def in module.ast.definitions() {
                    if let Definition::Validator(validator) = def {
                        analyzer.add_validator(validator.clone());
                    }
                }
            }
        }
        
        // Perform the analysis using symbolic execution
        analyzer.analyze();
        
        Ok(())
    });

    result.map_err(|_| process::exit(1))
} 