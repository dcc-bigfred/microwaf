//! CEL compile / eval helpers for rule `match` expressions.

use std::collections::HashMap;
use std::sync::Arc;

use cel_interpreter::{Context, Program, Value};

/// Compiled CEL program (Arc so Rule is cheap to clone).
#[derive(Clone)]
pub struct CompiledMatch {
    /// Source text.
    pub source: String,
    /// Compiled program.
    program: Arc<Program>,
}

impl std::fmt::Debug for CompiledMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledMatch")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Context bindings for a single evaluation.
#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    /// Dotted keys expanded into nested CEL maps (`request.method`, …).
    pub bindings: HashMap<String, CtxValue>,
    /// Named sets: name → members.
    pub sets: HashMap<String, Vec<String>>,
}

/// A context value.
#[derive(Debug, Clone)]
pub enum CtxValue {
    /// String.
    Str(String),
    /// Integer.
    Int(i64),
    /// Bool.
    Bool(bool),
    /// Bytes.
    Bytes(Vec<u8>),
}

impl MatchContext {
    /// Set a string binding.
    pub fn set_str(&mut self, key: impl Into<String>, v: impl Into<String>) {
        self.bindings.insert(key.into(), CtxValue::Str(v.into()));
    }

    /// Set an int binding.
    pub fn set_int(&mut self, key: impl Into<String>, v: i64) {
        self.bindings.insert(key.into(), CtxValue::Int(v));
    }

    /// Set a bool binding.
    pub fn set_bool(&mut self, key: impl Into<String>, v: bool) {
        self.bindings.insert(key.into(), CtxValue::Bool(v));
    }
}

fn to_value(v: &CtxValue) -> Value {
    match v {
        CtxValue::Str(s) => Value::String(Arc::new(s.clone())),
        CtxValue::Int(i) => Value::Int(*i),
        CtxValue::Bool(b) => Value::Bool(*b),
        CtxValue::Bytes(b) => Value::Bytes(Arc::new(b.clone())),
    }
}

/// Compile a CEL expression.
///
/// # Errors
/// Returns a human-readable compile error.
pub fn compile_match(src: &str) -> Result<CompiledMatch, String> {
    let program = Program::compile(src).map_err(|e| e.to_string())?;
    Ok(CompiledMatch {
        source: src.to_string(),
        program: Arc::new(program),
    })
}

/// Evaluate a compiled match against a context. Returns false on eval error.
#[must_use]
pub fn eval_match(prog: &CompiledMatch, ctx: &MatchContext) -> bool {
    let mut cel_ctx = Context::default();

    let mut roots: HashMap<String, HashMap<String, Value>> = HashMap::new();
    let mut top: HashMap<String, Value> = HashMap::new();

    for (k, v) in &ctx.bindings {
        let val = to_value(v);
        if let Some((root, rest)) = k.split_once('.') {
            roots
                .entry(root.to_string())
                .or_default()
                .insert(rest.to_string(), val);
        } else {
            top.insert(k.clone(), val);
        }
    }

    for (root, fields) in roots {
        let map: HashMap<String, Value> = fields;
        cel_ctx.add_variable_from_value(&root, Value::from(map));
    }
    for (k, v) in top {
        cel_ctx.add_variable_from_value(&k, v);
    }

    let sets_map: HashMap<String, Value> = ctx
        .sets
        .iter()
        .map(|(name, members)| {
            let list = Value::List(Arc::new(
                members
                    .iter()
                    .map(|m| Value::String(Arc::new(m.clone())))
                    .collect(),
            ));
            (name.clone(), list)
        })
        .collect();
    cel_ctx.add_variable_from_value("sets", Value::from(sets_map));

    match prog.program.execute(&cel_ctx) {
        Ok(Value::Bool(b)) => b,
        Ok(_) => false,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_equality() {
        let prog = compile_match(r#"request.method == "POST""#).unwrap();
        let mut ctx = MatchContext::default();
        ctx.set_str("request.method", "POST");
        assert!(eval_match(&prog, &ctx));
        ctx.set_str("request.method", "GET");
        assert!(!eval_match(&prog, &ctx));
    }

    #[test]
    fn z21_header() {
        let prog = compile_match("z21.header == 64 && z21.xheader == 228").unwrap();
        let mut ctx = MatchContext::default();
        ctx.set_int("z21.header", 0x40);
        ctx.set_int("z21.xheader", 0xE4);
        assert!(eval_match(&prog, &ctx));
    }
}
