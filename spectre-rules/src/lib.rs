use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use regex::Regex;
use serde::Deserialize;
use anyhow::{bail, Result};
use ipnet::IpNet;

#[derive(Debug, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub detection: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quantifier {
    All,
    Count(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Them,
    Pattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstNode {
    Selection(String),
    Cardinality { quantifier: Quantifier, target: Target },
    Not(Box<AstNode>),
    And(Box<AstNode>, Box<AstNode>),
    Or(Box<AstNode>, Box<AstNode>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Ident(String),
    Number(usize),
    And,
    Or,
    Not,
    All,
    Of,
    Them,
    LParen,
    RParen,
    Eof,
}

pub struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input: input.as_bytes(), pos: 0 }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                tokens.push(Token::Eof);
                break;
            }

            match self.input[self.pos] {
                b'(' => { self.pos += 1; tokens.push(Token::LParen); }
                b')' => { self.pos += 1; tokens.push(Token::RParen); }
                b'0'..=b'9' => {
                    let start = self.pos;
                    while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                        self.pos += 1;
                    }
                    let num_str = std::str::from_utf8(&self.input[start..self.pos])?;
                    let val: usize = num_str.parse()?;
                    tokens.push(Token::Number(val));
                }
                _ => {
                    let start = self.pos;
                    while self.pos < self.input.len() && is_ident_char(self.input[self.pos]) {
                        self.pos += 1;
                    }
                    if start == self.pos {
                        bail!("Unexpected character '{}' at byte {}", self.input[self.pos] as char, self.pos);
                    }
                    let word = std::str::from_utf8(&self.input[start..self.pos])?;
                    let token = match () {
                        _ if word.eq_ignore_ascii_case("and") => Token::And,
                        _ if word.eq_ignore_ascii_case("or") => Token::Or,
                        _ if word.eq_ignore_ascii_case("not") => Token::Not,
                        _ if word.eq_ignore_ascii_case("all") => Token::All,
                        _ if word.eq_ignore_ascii_case("of") => Token::Of,
                        _ if word.eq_ignore_ascii_case("them") => Token::Them,
                        _ => Token::Ident(word.to_string()),
                    };
                    tokens.push(token);
                }
            }
        }
        Ok(tokens)
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
}

#[inline]
fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'*' || c == b'?'
}

pub struct Parser {
    tokens: Vec<Token>,
    idx: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, idx: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.idx]
    }

    fn consume(&mut self) -> Token {
        let tok = self.tokens[self.idx].clone();
        if self.idx < self.tokens.len() - 1 {
            self.idx += 1;
        }
        tok
    }

    pub fn parse(&mut self) -> Result<AstNode> {
        let ast = self.parse_expr(0)?;
        if self.peek() != &Token::Eof {
            bail!("Unexpected trailing token: {:?}", self.peek());
        }
        Ok(ast)
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<AstNode> {
        let mut lhs = self.parse_prefix()?;

        loop {
            let (left_bp, right_bp) = match self.peek() {
                Token::Or => (1, 2),
                Token::And => (3, 4),
                _ => break,
            };

            if left_bp < min_bp {
                break;
            }

            let op = self.consume();
            let rhs = self.parse_expr(right_bp)?;
            lhs = match op {
                Token::Or => AstNode::Or(Box::new(lhs), Box::new(rhs)),
                Token::And => AstNode::And(Box::new(lhs), Box::new(rhs)),
                _ => unreachable!(),
            };
        }

        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<AstNode> {
        match self.consume() {
            Token::Not => {
                let rhs = self.parse_expr(5)?;
                Ok(AstNode::Not(Box::new(rhs)))
            }
            Token::LParen => {
                let inner = self.parse_expr(0)?;
                if self.consume() != Token::RParen {
                    bail!("Expected closing parenthesis ')'");
                }
                Ok(inner)
            }
            Token::All => {
                if self.consume() != Token::Of {
                    bail!("Expected 'of' after 'all'");
                }
                let target = self.parse_target()?;
                Ok(AstNode::Cardinality {
                    quantifier: Quantifier::All,
                    target,
                })
            }
            Token::Number(n) => {
                if self.consume() != Token::Of {
                    bail!("Expected 'of' after count '{}'", n);
                }
                let target = self.parse_target()?;
                Ok(AstNode::Cardinality {
                    quantifier: Quantifier::Count(n),
                    target,
                })
            }
            Token::Ident(id) => Ok(AstNode::Selection(id)),
            tok => bail!("Unexpected prefix token: {:?}", tok),
        }
    }

    fn parse_target(&mut self) -> Result<Target> {
        match self.consume() {
            Token::Them => Ok(Target::Them),
            Token::Ident(pattern) => Ok(Target::Pattern(pattern)),
            tok => bail!("Expected 'them' or pattern identifier, found {:?}", tok),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SelectionId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueListLogic {
    Any,
    All,
}

#[derive(Debug, Clone)]
pub enum ValueMatcher {
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Arc<Regex>),
    Cidr(IpNet),
}

impl ValueMatcher {
    #[inline]
    pub fn matches(&self, field_val: &str) -> bool {
        match self {
            Self::Equals(v) => field_val.eq_ignore_ascii_case(v),
            Self::Contains(v) => {
                let haystack = field_val.to_ascii_lowercase();
                let needle = v.to_ascii_lowercase();
                haystack.contains(&needle)
            }
            Self::StartsWith(v) => {
                let haystack = field_val.to_ascii_lowercase();
                let needle = v.to_ascii_lowercase();
                haystack.starts_with(&needle)
            }
            Self::EndsWith(v) => {
                let haystack = field_val.to_ascii_lowercase();
                let needle = v.to_ascii_lowercase();
                haystack.ends_with(&needle)
            }
            Self::Regex(re) => re.is_match(field_val),
            Self::Cidr(net) => {
                if let Ok(ip) = field_val.trim().parse::<IpAddr>() {
                    net.contains(&ip)
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledFieldCondition {
    pub field: String,
    pub logic: ValueListLogic,
    pub matchers: Vec<ValueMatcher>,
}

impl CompiledFieldCondition {
    pub fn evaluate(&self, event: &HashMap<String, String>) -> bool {
        let field_val = match event.get(&self.field) {
            Some(v) => v.as_str(),
            None => "",
        };

        if self.matchers.is_empty() {
            return false;
        }

        match self.logic {
            ValueListLogic::Any => {
                for matcher in &self.matchers {
                    if matcher.matches(field_val) {
                        return true;
                    }
                }
                false
            }
            ValueListLogic::All => {
                for matcher in &self.matchers {
                    if !matcher.matches(field_val) {
                        return false;
                    }
                }
                true
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum CompiledExpr {
    Selection(SelectionId),
    Cardinality {
        required: usize,
        is_all: bool,
        selections: Vec<SelectionId>,
    },
    Not(Box<CompiledExpr>),
    And(Box<CompiledExpr>, Box<CompiledExpr>),
    Or(Box<CompiledExpr>, Box<CompiledExpr>),
}

pub struct SigmaEngine {
    pub selection_conditions: Vec<Vec<CompiledFieldCondition>>,
    pub condition_root: CompiledExpr,
    pub rule_title: String,
    pub rule_id: String,
}

impl SigmaEngine {
    pub fn parse(rule: &SigmaRule) -> Result<Self> {
        let mut raw_selections = HashMap::new();
        let mut condition_str = String::new();

        for (k, v) in &rule.detection {
            if k == "condition" {
                if let Some(s) = v.as_str() {
                    condition_str = s.to_string();
                }
            } else if let Some(map) = v.as_mapping() {
                let mut field_conds = Vec::new();
                for (field_key, field_val) in map {
                    let key = field_key.as_str().unwrap_or_default().to_string();
                    let parts: Vec<&str> = key.split('|').map(|s| s.trim()).collect();
                    let field = parts[0].to_string();
                    let modifiers: Vec<&str> = parts[1..].to_vec();

                    let has_all = modifiers.iter().any(|&m| m.eq_ignore_ascii_case("all"));
                    let logic = if has_all { ValueListLogic::All } else { ValueListLogic::Any };

                    let op_name = modifiers
                        .iter()
                        .find(|&&m| !m.eq_ignore_ascii_case("all"))
                        .copied()
                        .unwrap_or("equals");

                    let raw_strings: Vec<String> = match field_val {
                        serde_yaml::Value::Sequence(seq) => seq
                            .iter()
                            .map(|item| match item {
                                serde_yaml::Value::String(s) => s.clone(),
                                serde_yaml::Value::Number(n) => n.to_string(),
                                serde_yaml::Value::Bool(b) => b.to_string(),
                                _ => "".to_string(),
                            })
                            .collect(),
                        serde_yaml::Value::String(s) => vec![s.clone()],
                        serde_yaml::Value::Number(n) => vec![n.to_string()],
                        serde_yaml::Value::Bool(b) => vec![b.to_string()],
                        _ => vec![],
                    };

                    let mut matchers = Vec::with_capacity(raw_strings.len());
                    for s in raw_strings {
                        let matcher = match op_name.to_ascii_lowercase().as_str() {
                            "contains" => ValueMatcher::Contains(s),
                            "startswith" => ValueMatcher::StartsWith(s),
                            "endswith" => ValueMatcher::EndsWith(s),
                            "re" => ValueMatcher::Regex(Arc::new(Regex::new(&s)?)),
                            "cidr" => ValueMatcher::Cidr(s.parse::<IpNet>()?),
                            _ => ValueMatcher::Equals(s),
                        };
                        matchers.push(matcher);
                    }

                    field_conds.push(CompiledFieldCondition {
                        field,
                        logic,
                        matchers,
                    });
                }
                raw_selections.insert(k.clone(), field_conds);
            }
        }

        if condition_str.is_empty() {
            bail!("Missing condition in detection");
        }

        let mut lexer = Lexer::new(&condition_str);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser::new(tokens);
        let ast = parser.parse()?;

        let mut name_to_id = HashMap::new();
        let mut selection_conditions = Vec::new();

        for (name, conditions) in raw_selections {
            let id = SelectionId(selection_conditions.len());
            name_to_id.insert(name, id);
            selection_conditions.push(conditions);
        }

        let condition_root = Self::compile_node(&ast, &name_to_id)?;

        Ok(Self {
            selection_conditions,
            condition_root,
            rule_title: rule.title.clone(),
            rule_id: rule.id.clone(),
        })
    }

    fn compile_node(ast: &AstNode, name_to_id: &HashMap<String, SelectionId>) -> Result<CompiledExpr> {
        match ast {
            AstNode::Selection(name) => {
                let id = name_to_id.get(name)
                    .ok_or_else(|| anyhow::anyhow!("Undefined selection in condition: {}", name))?;
                Ok(CompiledExpr::Selection(*id))
            }
            AstNode::Cardinality { quantifier, target } => {
                let mut matched_ids = Vec::new();
                for (name, id) in name_to_id {
                    let matched = match target {
                        Target::Them => true,
                        Target::Pattern(pat) => glob_match(pat, name),
                    };
                    if matched {
                        matched_ids.push(*id);
                    }
                }
                let (required, is_all) = match quantifier {
                    Quantifier::All => (matched_ids.len(), true),
                    Quantifier::Count(n) => (*n, false),
                };
                Ok(CompiledExpr::Cardinality { required, is_all, selections: matched_ids })
            }
            AstNode::Not(inner) => Ok(CompiledExpr::Not(Box::new(Self::compile_node(inner, name_to_id)?))),
            AstNode::And(l, r) => Ok(CompiledExpr::And(
                Box::new(Self::compile_node(l, name_to_id)?),
                Box::new(Self::compile_node(r, name_to_id)?),
            )),
            AstNode::Or(l, r) => Ok(CompiledExpr::Or(
                Box::new(Self::compile_node(l, name_to_id)?),
                Box::new(Self::compile_node(r, name_to_id)?),
            )),
        }
    }

    pub fn evaluate(&self, event: &HashMap<String, String>) -> bool {
        let mut memo = vec![None; self.selection_conditions.len()];
        self.eval_expr(&self.condition_root, event, &mut memo)
    }

    fn eval_expr(&self, expr: &CompiledExpr, event: &HashMap<String, String>, memo: &mut [Option<bool>]) -> bool {
        match expr {
            CompiledExpr::Selection(id) => self.eval_selection(*id, event, memo),
            CompiledExpr::Not(inner) => !self.eval_expr(inner, event, memo),
            CompiledExpr::And(left, right) => {
                self.eval_expr(left, event, memo) && self.eval_expr(right, event, memo)
            }
            CompiledExpr::Or(left, right) => {
                self.eval_expr(left, event, memo) || self.eval_expr(right, event, memo)
            }
            CompiledExpr::Cardinality { required, is_all, selections } => {
                let mut matches = 0;
                for id in selections {
                    if self.eval_selection(*id, event, memo) {
                        matches += 1;
                        if !is_all && matches >= *required {
                            return true;
                        }
                    } else if *is_all {
                        return false;
                    }
                }
                matches >= *required
            }
        }
    }

    fn eval_selection(&self, id: SelectionId, event: &HashMap<String, String>, memo: &mut [Option<bool>]) -> bool {
        if let Some(cached) = memo[id.0] {
            return cached;
        }

        let conditions = &self.selection_conditions[id.0];
        let mut matched = true;

        for cond in conditions {
            if !cond.evaluate(event) {
                matched = false;
                break;
            }
        }

        memo[id.0] = Some(matched);
        matched
    }
}

fn glob_match(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" { return true; }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return candidate.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return candidate.ends_with(suffix);
    }
    pattern == candidate
}
