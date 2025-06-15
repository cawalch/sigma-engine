//! SIGMA condition expression parsing.
//!
//! This module provides tokenization and parsing of SIGMA condition expressions
//! into an Abstract Syntax Tree (AST) for bytecode generation.

use crate::error::{Result, SigmaError};
use crate::ir::PrimitiveId;
use std::collections::HashMap;

/// Represents tokens in a SIGMA condition expression.
///
/// These tokens are the building blocks of SIGMA condition expressions,
/// supporting both basic boolean logic and SIGMA-specific constructs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token {
    Identifier(String),
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
    Of,
    Them,
    All,
    Number(u32),
    Wildcard(String),
}

/// Abstract Syntax Tree for SIGMA condition expressions.
///
/// This AST represents the parsed structure of a SIGMA condition,
/// supporting both basic boolean logic and SIGMA-specific constructs
/// like count patterns.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum ConditionAst {
    Identifier(String),
    And(Box<ConditionAst>, Box<ConditionAst>),
    Or(Box<ConditionAst>, Box<ConditionAst>),
    Not(Box<ConditionAst>),
    OneOfThem,
    AllOfThem,
    OneOfPattern(String),
    AllOfPattern(String),
    CountOfPattern(u32, String),
}

/// Recursive descent parser for SIGMA condition expressions.
///
/// This parser implements a standard recursive descent algorithm
/// with proper operator precedence for SIGMA condition expressions.
pub(crate) struct ConditionParser<'a> {
    tokens: &'a [Token],
    position: usize,
    selection_map: &'a HashMap<String, Vec<PrimitiveId>>,
}

impl<'a> ConditionParser<'a> {
    /// Create a new condition parser.
    ///
    /// # Arguments
    /// * `tokens` - The tokenized condition expression
    /// * `selection_map` - Mapping from selection names to primitive IDs
    pub(crate) fn new(
        tokens: &'a [Token],
        selection_map: &'a HashMap<String, Vec<PrimitiveId>>,
    ) -> Self {
        Self {
            tokens,
            position: 0,
            selection_map,
        }
    }

    fn current_token(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.current_token().cloned();
        self.position += 1;
        token
    }

    /// Parse OR expressions (lowest precedence).
    ///
    /// Grammar: or_expr := and_expr ('or' and_expr)*
    pub(crate) fn parse_or_expression(&mut self) -> Result<ConditionAst> {
        let mut left = self.parse_and_expression()?;

        while let Some(Token::Or) = self.current_token() {
            self.advance();
            let right = self.parse_and_expression()?;
            left = ConditionAst::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// Parse AND expressions (medium precedence).
    ///
    /// Grammar: and_expr := not_expr ('and' not_expr)*
    fn parse_and_expression(&mut self) -> Result<ConditionAst> {
        let mut left = self.parse_not_expression()?;

        while let Some(Token::And) = self.current_token() {
            self.advance();
            let right = self.parse_not_expression()?;
            left = ConditionAst::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// Parse NOT expressions (highest precedence).
    ///
    /// Grammar: not_expr := 'not' primary | primary
    fn parse_not_expression(&mut self) -> Result<ConditionAst> {
        if let Some(Token::Not) = self.current_token() {
            self.advance();
            let operand = self.parse_primary()?;
            Ok(ConditionAst::Not(Box::new(operand)))
        } else {
            self.parse_primary()
        }
    }

    /// Parse primary expressions (identifiers, parentheses, special constructs).
    ///
    /// Grammar: primary := '(' or_expr ')' | identifier | number 'of' (them | pattern) | 'all' 'of' (them | pattern)
    fn parse_primary(&mut self) -> Result<ConditionAst> {
        match self.current_token() {
            Some(Token::LeftParen) => {
                self.advance();
                let expr = self.parse_or_expression()?;
                if let Some(Token::RightParen) = self.current_token() {
                    self.advance();
                    Ok(expr)
                } else {
                    Err(SigmaError::CompilationError(
                        "Expected closing parenthesis".to_string(),
                    ))
                }
            }
            Some(Token::Identifier(name)) => {
                let name = name.clone();
                self.advance();

                if self.selection_map.contains_key(&name) {
                    Ok(ConditionAst::Identifier(name))
                } else {
                    Err(SigmaError::CompilationError(format!(
                        "Unknown selection identifier: {}",
                        name
                    )))
                }
            }
            Some(Token::Number(n)) => {
                let count = *n;
                self.advance();

                if let Some(Token::Of) = self.current_token() {
                    self.advance();

                    match self.current_token() {
                        Some(Token::Them) => {
                            self.advance();
                            if count == 1 {
                                Ok(ConditionAst::OneOfThem)
                            } else {
                                Err(SigmaError::CompilationError(
                                    "Only '1 of them' is currently supported".to_string(),
                                ))
                            }
                        }
                        Some(Token::Wildcard(pattern)) => {
                            let pattern = pattern.clone();
                            self.advance();
                            Ok(ConditionAst::CountOfPattern(count, pattern))
                        }
                        _ => Err(SigmaError::CompilationError(
                            "Expected 'them' or pattern after 'of'".to_string(),
                        )),
                    }
                } else {
                    Err(SigmaError::CompilationError(
                        "Expected 'of' after number".to_string(),
                    ))
                }
            }
            Some(Token::All) => {
                self.advance();

                if let Some(Token::Of) = self.current_token() {
                    self.advance();

                    match self.current_token() {
                        Some(Token::Them) => {
                            self.advance();
                            Ok(ConditionAst::AllOfThem)
                        }
                        Some(Token::Wildcard(pattern)) => {
                            let pattern = pattern.clone();
                            self.advance();
                            Ok(ConditionAst::AllOfPattern(pattern))
                        }
                        _ => Err(SigmaError::CompilationError(
                            "Expected 'them' or pattern after 'of'".to_string(),
                        )),
                    }
                } else {
                    Err(SigmaError::CompilationError(
                        "Expected 'of' after 'all'".to_string(),
                    ))
                }
            }
            _ => Err(SigmaError::CompilationError(
                "Unexpected token in condition".to_string(),
            )),
        }
    }
}

/// Tokenize a SIGMA condition string into tokens.
///
/// This function performs lexical analysis on a SIGMA condition string,
/// breaking it down into tokens that can be parsed into an AST.
///
/// # Arguments
/// * `condition` - The condition string to tokenize
///
/// # Returns
/// A vector of tokens representing the condition expression.
///
/// # Errors
/// Returns an error if the condition contains invalid syntax.
pub(crate) fn tokenize_condition(condition: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = condition.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LeftParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RightParen);
                chars.next();
            }
            '0'..='9' => {
                let mut number_str = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_digit() {
                        number_str.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Ok(num) = number_str.parse::<u32>() {
                    tokens.push(Token::Number(num));
                }
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                let mut identifier = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' || ch == '*' {
                        identifier.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }

                match identifier.as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    "of" => tokens.push(Token::Of),
                    "them" => tokens.push(Token::Them),
                    "all" => tokens.push(Token::All),
                    _ => {
                        if identifier.contains('*') {
                            tokens.push(Token::Wildcard(identifier));
                        } else {
                            tokens.push(Token::Identifier(identifier));
                        }
                    }
                }
            }
            _ => {
                return Err(SigmaError::CompilationError(format!(
                    "Unexpected character in condition: '{}'",
                    ch
                )));
            }
        }
    }

    Ok(tokens)
}

/// Parse tokens into an AST using recursive descent parsing.
///
/// # Arguments
/// * `tokens` - The tokens to parse
/// * `selection_map` - Mapping from selection names to primitive IDs
///
/// # Returns
/// The parsed AST representing the condition expression.
pub(crate) fn parse_tokens(
    tokens: &[Token],
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
) -> Result<ConditionAst> {
    if tokens.is_empty() {
        return Err(SigmaError::CompilationError("Empty condition".to_string()));
    }

    let mut parser = ConditionParser::new(tokens, selection_map);
    parser.parse_or_expression()
}
