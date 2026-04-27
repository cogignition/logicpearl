// SPDX-License-Identifier: MIT
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use logicpearl_discovery::ProgressEvent;
use std::io::IsTerminal;

pub(super) fn progress_enabled(_json: bool, progress: bool) -> bool {
    progress
}

pub(super) enum CliProgress {
    Spinner(ProgressBar),
    Lines,
}

pub(super) fn start_progress(
    enabled: bool,
    initial_message: impl Into<String>,
) -> Option<CliProgress> {
    if !enabled {
        return None;
    }
    let initial_message = initial_message.into();
    if std::io::stderr().is_terminal() {
        let sp = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
        sp.set_style(ProgressStyle::with_template("{spinner:.green} {msg} ({elapsed})").unwrap());
        sp.enable_steady_tick(std::time::Duration::from_millis(80));
        sp.set_message(initial_message);
        sp.tick();
        Some(CliProgress::Spinner(sp))
    } else {
        eprintln!("{initial_message}");
        Some(CliProgress::Lines)
    }
}

pub(super) fn progress_callback(
    progress: Option<&CliProgress>,
) -> Option<Box<dyn Fn(ProgressEvent) + Send + Sync>> {
    progress.map(|progress| match progress {
        CliProgress::Spinner(sp) => {
            let sp = sp.clone();
            Box::new(move |event: ProgressEvent| {
                sp.set_message(event.message);
                sp.tick();
            }) as Box<dyn Fn(ProgressEvent) + Send + Sync>
        }
        CliProgress::Lines => Box::new(move |event: ProgressEvent| {
            eprintln!("{}", event.message);
        }) as Box<dyn Fn(ProgressEvent) + Send + Sync>,
    })
}

pub(super) fn set_progress_message(progress: Option<&CliProgress>, message: impl Into<String>) {
    let Some(progress) = progress else {
        return;
    };
    let message = message.into();
    match progress {
        CliProgress::Spinner(sp) => {
            sp.set_message(message);
            sp.tick();
        }
        CliProgress::Lines => eprintln!("{message}"),
    }
}

pub(super) fn finish_progress(progress: Option<CliProgress>) {
    if let Some(CliProgress::Spinner(sp)) = progress {
        sp.finish_and_clear();
    }
}
