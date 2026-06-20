use std::collections::HashMap;
use regex::Regex;
use serde::Deserialize;
use anyhow::{Result, bail};

#[derive(Debug, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub detection: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone)]
pub enum Operator {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

#[derive(Debug, Clone)]
pub struct FieldCondition {
    pub field: String,
    pub operator: Operator,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum AstNode {
    Selection(String),
    And(Box<AstNode>, Box<AstNode>),
    Or(Box<AstNode>, Box<AstNode>),
    Not(Box<AstNode>),
}

pub struct SigmaEngine {
    pub selections: HashMap<String, Vec<FieldCondition>>,
    pub condition_ast: AstNode,
}

impl SigmaEngine {
    pub fn parse(rule: &SigmaRule) -> Result<Self> {
        let mut selections = HashMap::new();
        let mut condition_str = String::new();

        for (k, v) in &rule.detection {
            if k == "condition" {
                if let Some(s) = v.as_str() {
                    condition_str = s.to_string();
                }
            } else if let Some(map) = v.as_mapping() {
                let mut conditions = Vec::new();
                for (field_key, field_val) in map {
                    let key = field_key.as_str().unwrap_or_default().to_string();
                    let val = field_val.as_str().unwrap_or_default().to_string();
                    
                    let parts: Vec<&str> = key.split('|').collect();
                    let field = parts[0].to_string();
                    let operator = if parts.len() > 1 {
                        match parts[1] {
                            "contains" => Operator::Contains,
                            "endswith" => Operator::EndsWith,
                            "startswith" => Operator::StartsWith,
                            "re" => Operator::Regex,
                            _ => Operator::Equals,
                        }
                    } else {
                        Operator::Equals
                    };
                    conditions.push(FieldCondition { field, operator, value: val });
                }
                selections.insert(k.clone(), conditions);
            }
        }

        if condition_str.is_empty() {
            bail!("Missing condition");
        }

        // Extremely simplified AST parser for MVP: just supports "sel1 and sel2"
        // A real parser would use `nom` or `pest`.
        let tokens: Vec<&str> = condition_str.split_whitespace().collect();
        let ast = if tokens.len() == 3 && tokens[1].to_lowercase() == "and" {
            AstNode::And(
                Box::new(AstNode::Selection(tokens[0].to_string())),
                Box::new(AstNode::Selection(tokens[2].to_string())),
            )
        } else if tokens.len() == 3 && tokens[1].to_lowercase() == "or" {
            AstNode::Or(
                Box::new(AstNode::Selection(tokens[0].to_string())),
                Box::new(AstNode::Selection(tokens[2].to_string())),
            )
        } else if tokens.len() == 1 {
            AstNode::Selection(tokens[0].to_string())
        } else {
            // Fallback for MVP: just wrap the first token
            AstNode::Selection(tokens[0].to_string())
        };

        Ok(Self {
            selections,
            condition_ast: ast,
        })
    }

    pub fn evaluate(&self, event: &HashMap<String, String>) -> bool {
        self.eval_node(&self.condition_ast, event)
    }

    fn eval_node(&self, node: &AstNode, event: &HashMap<String, String>) -> bool {
        match node {
            AstNode::Selection(name) => {
                if let Some(conditions) = self.selections.get(name) {
                    // All conditions in a selection must match (AND)
                    for cond in conditions {
                        let field_val = event.get(&cond.field).map(|s| s.as_str()).unwrap_or("");
                        let matched = match cond.operator {
                            Operator::Equals => field_val == cond.value,
                            Operator::Contains => field_val.contains(&cond.value),
                            Operator::StartsWith => field_val.starts_with(&cond.value),
                            Operator::EndsWith => field_val.ends_with(&cond.value),
                            Operator::Regex => {
                                if let Ok(re) = Regex::new(&cond.value) {
                                    re.is_match(field_val)
                                } else {
                                    false
                                }
                            }
                        };
                        if !matched {
                            return false;
                        }
                    }
                    true
                } else {
                    false
                }
            }
            AstNode::And(left, right) => self.eval_node(left, event) && self.eval_node(right, event),
            AstNode::Or(left, right) => self.eval_node(left, event) || self.eval_node(right, event),
            AstNode::Not(inner) => !self.eval_node(inner, event),
        }
    }
}
