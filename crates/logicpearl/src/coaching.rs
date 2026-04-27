// SPDX-License-Identifier: MIT

/// Structured helper for CLI failures that should coach the next step.
///
/// Keep command errors in this shape so failures read consistently across the
/// CLI instead of every command inventing its own expected/found/next wording.
#[derive(Debug, Clone)]
pub(crate) struct CommandCoaching {
    message: String,
    expected: String,
    found: String,
    next: String,
    related: Vec<String>,
}

impl CommandCoaching {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            found: message.clone(),
            message,
            expected: "valid inputs for this LogicPearl command".to_string(),
            next: "rerun the command with corrected inputs".to_string(),
            related: Vec::new(),
        }
    }

    pub(crate) fn simple(message: impl Into<String>, next: impl Into<String>) -> miette::Report {
        Self::new(message).next(next).into_report()
    }

    pub(crate) fn expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = expected.into();
        self
    }

    pub(crate) fn found(mut self, found: impl Into<String>) -> Self {
        self.found = found.into();
        self
    }

    pub(crate) fn next(mut self, next: impl Into<String>) -> Self {
        self.next = next.into();
        self
    }

    pub(crate) fn docs(mut self, docs: impl Into<String>) -> Self {
        self.related.push(format!("Docs: {}", docs.into()));
        self
    }

    pub(crate) fn example(mut self, example: impl Into<String>) -> Self {
        self.related.push(format!("Example: {}", example.into()));
        self
    }

    pub(crate) fn into_report(self) -> miette::Report {
        let mut help = format!(
            "Expected: {}\nFound: {}\nNext: {}",
            self.expected, self.found, self.next
        );
        if !self.related.is_empty() {
            help.push_str("\nRelated:");
            for related in self.related {
                help.push_str("\n  - ");
                help.push_str(&related);
            }
        }
        miette::miette!(help = help, "{}", self.message)
    }
}
