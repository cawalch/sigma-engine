//! SIGMA condition expression parsing.
//!
//! This module provides tokenization and parsing of SIGMA condition expressions
//! into an Abstract Syntax Tree (AST) for bytecode generation.

use crate::error::{Result, SigmaError};
use crate::ir::PrimitiveId;
use std::collections::HashMap;

/// Tokens in a SIGMA condition expression.
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

/// AST for SIGMA condition expressions.
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

/// Recursive descent parser for SIGMA conditions.
pub(crate) struct ConditionParser<'a> {
    tokens: &'a [Token],
    position: usize,
    selection_map: &'a HashMap<String, Vec<PrimitiveId>>,
}

impl<'a> ConditionParser<'a> {
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
    fn parse_not_expression(&mut self) -> Result<ConditionAst> {
        if let Some(Token::Not) = self.current_token() {
            self.advance();
            let operand = self.parse_primary()?;
            Ok(ConditionAst::Not(Box::new(operand)))
        } else {
            self.parse_primary()
        }
    }

    /// Parse primary expressions.
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
                                    "Only '1 of them' is supported".to_string(),
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

/// Tokenize a SIGMA condition string.
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

/// Parse tokens into an AST.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_selection_map() -> HashMap<String, Vec<PrimitiveId>> {
        let mut map = HashMap::new();
        map.insert("selection1".to_string(), vec![0]);
        map.insert("selection2".to_string(), vec![1]);
        map.insert("selection3".to_string(), vec![2]);
        map
    }

    #[test]
    fn test_tokenize_simple_identifier() {
        let result = tokenize_condition("selection1");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Identifier(ref s) if s == "selection1"));
    }

    #[test]
    fn test_tokenize_and_expression() {
        let result = tokenize_condition("selection1 and selection2");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Identifier(_)));
        assert!(matches!(tokens[1], Token::And));
        assert!(matches!(tokens[2], Token::Identifier(_)));
    }

    #[test]
    fn test_tokenize_or_expression() {
        let result = tokenize_condition("selection1 or selection2");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Identifier(_)));
        assert!(matches!(tokens[1], Token::Or));
        assert!(matches!(tokens[2], Token::Identifier(_)));
    }

    #[test]
    fn test_tokenize_not_expression() {
        let result = tokenize_condition("not selection1");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], Token::Not));
        assert!(matches!(tokens[1], Token::Identifier(_)));
    }

    #[test]
    fn test_tokenize_parentheses() {
        let result = tokenize_condition("(selection1 and selection2)");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 5);
        assert!(matches!(tokens[0], Token::LeftParen));
        assert!(matches!(tokens[1], Token::Identifier(_)));
        assert!(matches!(tokens[2], Token::And));
        assert!(matches!(tokens[3], Token::Identifier(_)));
        assert!(matches!(tokens[4], Token::RightParen));
    }

    #[test]
    fn test_tokenize_numbers() {
        let result = tokenize_condition("2 of selection*");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Number(2)));
        assert!(matches!(tokens[1], Token::Of));
        assert!(matches!(tokens[2], Token::Wildcard(_)));
    }

    #[test]
    fn test_tokenize_wildcard() {
        let result = tokenize_condition("selection*");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Wildcard(ref s) if s == "selection*"));
    }

    #[test]
    fn test_tokenize_all_of_them() {
        let result = tokenize_condition("all of them");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::All));
        assert!(matches!(tokens[1], Token::Of));
        assert!(matches!(tokens[2], Token::Them));
    }

    #[test]
    fn test_tokenize_one_of_them() {
        let result = tokenize_condition("1 of them");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Number(1)));
        assert!(matches!(tokens[1], Token::Of));
        assert!(matches!(tokens[2], Token::Them));
    }

    #[test]
    fn test_tokenize_invalid_character() {
        let result = tokenize_condition("selection1 @ selection2");
        assert!(result.is_err());
        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Unexpected character"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_tokenize_whitespace_handling() {
        let result = tokenize_condition("  selection1   and   selection2  ");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
    }

    #[test]
    fn test_parse_simple_identifier() {
        let tokens = vec![Token::Identifier("selection1".to_string())];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::Identifier(ref s) if s == "selection1"));
    }

    #[test]
    fn test_parse_and_expression() {
        let tokens = vec![
            Token::Identifier("selection1".to_string()),
            Token::And,
            Token::Identifier("selection2".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::And(_, _)));
    }

    #[test]
    fn test_parse_or_expression() {
        let tokens = vec![
            Token::Identifier("selection1".to_string()),
            Token::Or,
            Token::Identifier("selection2".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::Or(_, _)));
    }

    #[test]
    fn test_parse_not_expression() {
        let tokens = vec![Token::Not, Token::Identifier("selection1".to_string())];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::Not(_)));
    }

    #[test]
    fn test_parse_parentheses() {
        let tokens = vec![
            Token::LeftParen,
            Token::Identifier("selection1".to_string()),
            Token::And,
            Token::Identifier("selection2".to_string()),
            Token::RightParen,
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::And(_, _)));
    }

    #[test]
    fn test_parse_all_of_them() {
        let tokens = vec![Token::All, Token::Of, Token::Them];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::AllOfThem));
    }

    #[test]
    fn test_parse_one_of_them() {
        let tokens = vec![Token::Number(1), Token::Of, Token::Them];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::OneOfThem));
    }

    #[test]
    fn test_parse_count_of_pattern() {
        let tokens = vec![
            Token::Number(2),
            Token::Of,
            Token::Wildcard("selection*".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::CountOfPattern(2, ref s) if s == "selection*"));
    }

    #[test]
    fn test_parse_all_of_pattern() {
        let tokens = vec![
            Token::All,
            Token::Of,
            Token::Wildcard("selection*".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::AllOfPattern(ref s) if s == "selection*"));
    }

    #[test]
    fn test_parse_one_of_pattern() {
        let tokens = vec![
            Token::Number(1),
            Token::Of,
            Token::Wildcard("selection*".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        // "1 of pattern" should parse as CountOfPattern(1, pattern)
        assert!(matches!(ast, ConditionAst::CountOfPattern(1, ref s) if s == "selection*"));
    }

    #[test]
    fn test_parse_empty_tokens() {
        let tokens = vec![];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Empty condition"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_parse_missing_closing_parenthesis() {
        let tokens = vec![
            Token::LeftParen,
            Token::Identifier("selection1".to_string()),
            Token::And,
            Token::Identifier("selection2".to_string()),
            // Missing RightParen
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Expected closing parenthesis"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_parse_invalid_after_all() {
        let tokens = vec![
            Token::All,
            Token::Identifier("invalid".to_string()), // Should be "of"
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Expected 'of' after 'all'"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_parse_invalid_after_of() {
        let tokens = vec![
            Token::All,
            Token::Of,
            Token::Identifier("invalid".to_string()), // Should be "them" or wildcard
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Expected 'them' or pattern after 'of'"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_parse_unexpected_token() {
        let tokens = vec![
            Token::RightParen, // Unexpected token at start
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Unexpected token in condition"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_parse_complex_expression() {
        // Test: (selection1 and selection2) or not selection3
        let tokens = vec![
            Token::LeftParen,
            Token::Identifier("selection1".to_string()),
            Token::And,
            Token::Identifier("selection2".to_string()),
            Token::RightParen,
            Token::Or,
            Token::Not,
            Token::Identifier("selection3".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::Or(_, _)));
    }

    #[test]
    fn test_parse_operator_precedence() {
        // Test: selection1 and selection2 or selection3 (should be (selection1 and selection2) or selection3)
        let tokens = vec![
            Token::Identifier("selection1".to_string()),
            Token::And,
            Token::Identifier("selection2".to_string()),
            Token::Or,
            Token::Identifier("selection3".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        // Should be parsed as OR at the top level due to precedence
        assert!(matches!(ast, ConditionAst::Or(_, _)));
    }

    #[test]
    fn test_parse_multiple_numbers() {
        let result = tokenize_condition("123 of selection*");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Number(123)));
    }

    #[test]
    fn test_parse_zero_count() {
        let tokens = vec![
            Token::Number(0),
            Token::Of,
            Token::Wildcard("selection*".to_string()),
        ];
        let selection_map = create_test_selection_map();

        let result = parse_tokens(&tokens, &selection_map);
        assert!(result.is_ok());

        let ast = result.unwrap();
        assert!(matches!(ast, ConditionAst::CountOfPattern(0, _)));
    }

    #[test]
    fn test_tokenize_underscore_identifiers() {
        let result = tokenize_condition("_internal_selection");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Identifier(ref s) if s == "_internal_selection"));
    }

    #[test]
    fn test_tokenize_mixed_case() {
        let result = tokenize_condition("Selection1 AND Selection2");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Identifier(ref s) if s == "Selection1"));
        assert!(matches!(tokens[1], Token::Identifier(ref s) if s == "AND")); // Case sensitive
        assert!(matches!(tokens[2], Token::Identifier(ref s) if s == "Selection2"));
    }

    #[test]
    fn test_tokenize_alphanumeric_identifiers() {
        let result = tokenize_condition("selection123 and test456");
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Identifier(ref s) if s == "selection123"));
        assert!(matches!(tokens[1], Token::And));
        assert!(matches!(tokens[2], Token::Identifier(ref s) if s == "test456"));
    }
}
