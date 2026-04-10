use crate::SatStatus;
use logicpearl_core::{LogicPearlError, Result};
use std::collections::BTreeMap;

pub fn parse_sat_status(stdout: &str) -> Result<SatStatus> {
    match stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with(';'))
        .unwrap_or_default()
    {
        "sat" => Ok(SatStatus::Sat),
        "unsat" => Ok(SatStatus::Unsat),
        "unknown" => Ok(SatStatus::Unknown),
        other => Err(LogicPearlError::message(format!(
            "solver output did not start with sat/unsat/unknown: {other:?}"
        ))),
    }
}

pub fn parse_selected_bool_indexes(stdout: &str, prefix: &str, count: usize) -> Vec<usize> {
    let mut selected = Vec::new();
    for index in 0..count {
        let needle = format!("(define-fun {prefix}_{index} () Bool");
        if let Some(position) = stdout.find(&needle) {
            let remainder = &stdout[position + needle.len()..];
            if remainder.trim_start().starts_with("true") {
                selected.push(index);
            }
        }
    }
    selected
}

pub fn parse_value_bindings(stdout: &str) -> Result<BTreeMap<String, String>> {
    let value_text = stdout.lines().skip(1).collect::<Vec<_>>().join("\n");
    parse_value_bindings_body(&value_text)
}

fn parse_value_bindings_body(value_text: &str) -> Result<BTreeMap<String, String>> {
    if value_text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let parsed = Parser::new(value_text).parse_expr()?;
    let Expr::List(bindings) = parsed else {
        return Err(LogicPearlError::message(
            "solver get-value output must be a top-level list",
        ));
    };

    let mut values = BTreeMap::new();
    for binding in bindings {
        let Expr::List(parts) = binding else {
            return Err(LogicPearlError::message(
                "solver get-value output bindings must be lists",
            ));
        };
        if parts.len() != 2 {
            return Err(LogicPearlError::message(
                "solver get-value output bindings must contain exactly two expressions",
            ));
        }
        let Expr::Atom(symbol) = &parts[0] else {
            return Err(LogicPearlError::message(
                "solver get-value output binding names must be atoms",
            ));
        };
        values.insert(symbol.clone(), render_expr(&parts[1]));
    }

    Ok(values)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Atom(String),
    List(Vec<Expr>),
}

struct Parser<'a> {
    chars: Vec<char>,
    position: usize,
    source: &'a str,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            chars: source.chars().collect(),
            position: 0,
            source,
        }
    }

    fn parse_expr(mut self) -> Result<Expr> {
        self.skip_whitespace();
        let expr = self.parse_expr_inner()?;
        self.skip_whitespace();
        if self.position != self.chars.len() {
            return Err(LogicPearlError::message(format!(
                "unexpected trailing solver output near byte {}",
                self.position
            )));
        }
        Ok(expr)
    }

    fn parse_expr_inner(&mut self) -> Result<Expr> {
        self.skip_whitespace();
        match self.current() {
            Some('(') => self.parse_list(),
            Some('"') => self.parse_string(),
            Some(_) => self.parse_atom(),
            None => Err(LogicPearlError::message(format!(
                "unexpected end of solver output while parsing {}",
                self.source
            ))),
        }
    }

    fn parse_list(&mut self) -> Result<Expr> {
        self.expect('(')?;
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            match self.current() {
                Some(')') => {
                    self.position += 1;
                    return Ok(Expr::List(items));
                }
                Some(_) => items.push(self.parse_expr_inner()?),
                None => {
                    return Err(LogicPearlError::message(
                        "unterminated list in solver output",
                    ));
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<Expr> {
        let mut rendered = String::new();
        self.expect('"')?;
        rendered.push('"');
        while let Some(ch) = self.current() {
            rendered.push(ch);
            self.position += 1;
            match ch {
                '"' => {
                    if self.current() == Some('"') {
                        rendered.push('"');
                        self.position += 1;
                    } else {
                        return Ok(Expr::Atom(rendered));
                    }
                }
                '\\' => {
                    if let Some(next) = self.current() {
                        rendered.push(next);
                        self.position += 1;
                    }
                }
                _ => {}
            }
        }
        Err(LogicPearlError::message(
            "unterminated string literal in solver output",
        ))
    }

    fn parse_atom(&mut self) -> Result<Expr> {
        let start = self.position;
        while let Some(ch) = self.current() {
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }
            self.position += 1;
        }
        if start == self.position {
            return Err(LogicPearlError::message(
                "expected atom in solver output but found an empty token",
            ));
        }
        Ok(Expr::Atom(
            self.chars[start..self.position].iter().collect(),
        ))
    }

    fn skip_whitespace(&mut self) {
        while self.current().is_some_and(|ch| ch.is_whitespace()) {
            self.position += 1;
        }
    }

    fn current(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn expect(&mut self, expected: char) -> Result<()> {
        match self.current() {
            Some(ch) if ch == expected => {
                self.position += 1;
                Ok(())
            }
            other => Err(LogicPearlError::message(format!(
                "expected {expected:?} in solver output, found {other:?}"
            ))),
        }
    }
}

fn render_expr(expr: &Expr) -> String {
    match expr {
        Expr::Atom(atom) => atom.clone(),
        Expr::List(items) => format!(
            "({})",
            items.iter().map(render_expr).collect::<Vec<_>>().join(" ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_sat_status, parse_selected_bool_indexes, parse_value_bindings};
    use crate::SatStatus;

    #[test]
    fn parses_sat_unsat_and_unknown_status_lines() {
        assert_eq!(parse_sat_status("sat\n").unwrap(), SatStatus::Sat);
        assert_eq!(parse_sat_status("unsat\n").unwrap(), SatStatus::Unsat);
        assert_eq!(parse_sat_status("unknown\n").unwrap(), SatStatus::Unknown);
    }

    #[test]
    fn ignores_blank_lines_and_comments_before_status() {
        assert_eq!(
            parse_sat_status("\n; comment\nsat\n").unwrap(),
            SatStatus::Sat
        );
    }

    #[test]
    fn parses_selected_bool_indexes_from_model_output() {
        let stdout = r#"sat
(model
  (define-fun keep_0 () Bool
    false)
  (define-fun keep_1 () Bool
    true)
  (define-fun keep_2 () Bool
    true))
"#;
        assert_eq!(parse_selected_bool_indexes(stdout, "keep", 3), vec![1, 2]);
    }

    #[test]
    fn parses_get_value_bindings() {
        let stdout = r#"sat
((f_age 21.0)
 (f_name "alice")
 (f_ratio (/ 1.0 2.0)))
"#;
        let parsed = parse_value_bindings(stdout).unwrap();
        assert_eq!(parsed["f_age"], "21.0");
        assert_eq!(parsed["f_name"], "\"alice\"");
        assert_eq!(parsed["f_ratio"], "(/ 1.0 2.0)");
    }
}
