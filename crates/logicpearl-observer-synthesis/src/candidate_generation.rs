// SPDX-License-Identifier: MIT
use crate::signal_profiles::SignalProfile;
use logicpearl_observer::{
    compile_phrase_match_text, compiled_prompt_matches_phrase, CompiledPhraseMatchText,
    GuardrailsSignal,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const GAP_TOKEN: &str = "__gap__";
const AND_TOKEN: &str = "__and__";
const NEAR_TOKEN: &str = "__near__";
const AFTER_DELIM_TOKEN: &str = "__after_delim__";
const BEFORE_DELIM_TOKEN: &str = "__before_delim__";
const QUOTED_TOKEN: &str = "__quoted__";
const MAX_SKIPGRAM_SPAN: usize = 6;
const MAX_NEAR_PATTERN_SPAN: usize = 6;
const MAX_CONJUNCTION_SPAN: usize = 12;
const SMALL_CORPUS_CANDIDATE_FALLBACK_LIMIT: usize = 4;

pub(crate) struct CandidatePool {
    pub(crate) candidates: Vec<String>,
    pub(crate) positive_constraints: Vec<Vec<usize>>,
    pub(crate) negative_constraints: Vec<Vec<usize>>,
}

pub fn generate_phrase_candidates(
    profile: &SignalProfile,
    signal: GuardrailsSignal,
    positive_prompts: &[String],
    negative_prompts: &[String],
    max_candidates: usize,
) -> Vec<String> {
    rank_phrase_candidates(profile, signal, positive_prompts, negative_prompts)
        .into_iter()
        .take(max_candidates)
        .map(|(phrase, _, _)| phrase)
        .collect()
}

fn rank_phrase_candidates(
    profile: &SignalProfile,
    signal: GuardrailsSignal,
    positive_prompts: &[String],
    negative_prompts: &[String],
) -> Vec<(String, usize, usize)> {
    let mut positive_hits: BTreeMap<String, usize> = BTreeMap::new();
    let mut negative_hits: BTreeMap<String, usize> = BTreeMap::new();

    for prompt in positive_prompts {
        let seen: HashSet<String> = candidate_ngrams(profile, prompt, signal)
            .into_iter()
            .collect();
        for phrase in seen {
            *positive_hits.entry(phrase).or_default() += 1;
        }
    }
    for prompt in negative_prompts {
        let seen: HashSet<String> = candidate_ngrams(profile, prompt, signal)
            .into_iter()
            .collect();
        for phrase in seen {
            *negative_hits.entry(phrase).or_default() += 1;
        }
    }

    let mut ranked: Vec<(String, usize, usize)> = positive_hits
        .into_iter()
        .filter_map(|(phrase, pos_hits)| {
            let neg_hits = negative_hits.get(&phrase).copied().unwrap_or_default();
            let clean_small_corpus_hit = positive_prompts.len()
                <= SMALL_CORPUS_CANDIDATE_FALLBACK_LIMIT
                && pos_hits == 1
                && neg_hits == 0;
            let keep = match signal {
                GuardrailsSignal::SecretExfiltration => {
                    (pos_hits >= 2 && pos_hits >= neg_hits) || clean_small_corpus_hit
                }
                _ => pos_hits >= 2 || clean_small_corpus_hit,
            };
            keep.then_some((phrase, pos_hits, neg_hits))
        })
        .collect();

    ranked.sort_by(|left, right| {
        let left_score = left.1 as isize - left.2 as isize;
        let right_score = right.1 as isize - right.2 as isize;
        right_score
            .cmp(&left_score)
            .then(left.2.cmp(&right.2))
            .then(right.1.cmp(&left.1))
            .then(left.0.len().cmp(&right.0.len()))
            .then(left.0.cmp(&right.0))
    });

    ranked
}

pub fn candidate_ngrams(
    profile: &SignalProfile,
    prompt: &str,
    signal: GuardrailsSignal,
) -> Vec<String> {
    let (tokens, delimiter_boundaries, quoted_spans) = tokenize_with_structure(prompt);
    let compressed_tokens = content_tokens(&tokens);
    let merged_tokens = merge_fragmented_token_runs(&tokens);
    let lengths: &[usize] = match signal {
        GuardrailsSignal::SecretExfiltration => &[1, 2, 3],
        _ => &[2, 3, 4],
    };
    let mut out = BTreeSet::new();
    collect_candidate_windows(&tokens, signal, profile, lengths, &mut out);
    collect_candidate_windows(&compressed_tokens, signal, profile, lengths, &mut out);
    collect_candidate_windows(&merged_tokens, signal, profile, lengths, &mut out);
    collect_skipgram_windows(&tokens, signal, profile, lengths, &mut out);
    collect_skipgram_windows(&compressed_tokens, signal, profile, lengths, &mut out);
    collect_skipgram_windows(&merged_tokens, signal, profile, lengths, &mut out);
    collect_delimiter_windows(
        &tokens,
        &delimiter_boundaries,
        signal,
        profile,
        lengths,
        &mut out,
    );
    collect_quote_windows(&tokens, &quoted_spans, signal, profile, lengths, &mut out);
    collect_near_windows(&tokens, signal, profile, &mut out);
    collect_near_windows(&compressed_tokens, signal, profile, &mut out);
    collect_near_windows(&merged_tokens, signal, profile, &mut out);
    collect_conjunction_windows(&tokens, signal, profile, &mut out);
    collect_conjunction_windows(&compressed_tokens, signal, profile, &mut out);
    collect_conjunction_windows(&merged_tokens, signal, profile, &mut out);
    out.into_iter().collect()
}

fn collect_candidate_windows(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    lengths: &[usize],
    out: &mut BTreeSet<String>,
) {
    for &width in lengths {
        if width > tokens.len() {
            continue;
        }
        for window in tokens.windows(width) {
            if !candidate_window_is_useful(window, signal, profile) {
                continue;
            }
            let phrase = window.join(" ");
            if phrase.len() >= 3 {
                out.insert(phrase);
            }
        }
    }
}

fn collect_skipgram_windows(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    lengths: &[usize],
    out: &mut BTreeSet<String>,
) {
    if tokens.len() < 3 {
        return;
    }
    let candidate_lengths: Vec<usize> = lengths
        .iter()
        .copied()
        .filter(|width| *width >= 2)
        .collect();
    if candidate_lengths.is_empty() {
        return;
    }
    for &width in &candidate_lengths {
        collect_skipgram_width(tokens, signal, profile, width, out);
    }
}

fn collect_skipgram_width(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    width: usize,
    out: &mut BTreeSet<String>,
) {
    if width < 2 || tokens.len() < width + 1 {
        return;
    }
    let mut indexes = Vec::with_capacity(width);
    for start in 0..tokens.len() {
        indexes.clear();
        indexes.push(start);
        collect_skipgram_suffix(tokens, signal, profile, width, start, &mut indexes, out);
    }
}

fn collect_skipgram_suffix(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    width: usize,
    last_index: usize,
    indexes: &mut Vec<usize>,
    out: &mut BTreeSet<String>,
) {
    if indexes.len() == width {
        let selected_tokens: Vec<String> =
            indexes.iter().map(|index| tokens[*index].clone()).collect();
        if !candidate_window_is_useful(&selected_tokens, signal, profile) {
            return;
        }
        if !indexes.windows(2).any(|pair| pair[1] > pair[0] + 1) {
            return;
        }
        let mut pattern = Vec::with_capacity(width * 2 - 1);
        for (position, token) in selected_tokens.iter().enumerate() {
            if position > 0 && indexes[position] > indexes[position - 1] + 1 {
                pattern.push(GAP_TOKEN.to_string());
            }
            pattern.push(token.clone());
        }
        let phrase = pattern.join(" ");
        if phrase.len() >= 6 {
            out.insert(phrase);
        }
        return;
    }

    let remaining = width - indexes.len();
    let max_next = (last_index + MAX_SKIPGRAM_SPAN).min(tokens.len().saturating_sub(remaining));
    let mut next = last_index + 1;
    while next <= max_next {
        indexes.push(next);
        collect_skipgram_suffix(tokens, signal, profile, width, next, indexes, out);
        indexes.pop();
        next += 1;
    }
}

fn collect_delimiter_windows(
    tokens: &[String],
    delimiter_boundaries: &[usize],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    lengths: &[usize],
    out: &mut BTreeSet<String>,
) {
    for &boundary in delimiter_boundaries {
        for &width in lengths {
            if boundary + width <= tokens.len() {
                let after_window = &tokens[boundary..boundary + width];
                if candidate_window_is_useful(after_window, signal, profile) {
                    out.insert(format!("{AFTER_DELIM_TOKEN} {}", after_window.join(" ")));
                }
            }
            if boundary >= width {
                let before_window = &tokens[boundary - width..boundary];
                if candidate_window_is_useful(before_window, signal, profile) {
                    out.insert(format!("{} {BEFORE_DELIM_TOKEN}", before_window.join(" ")));
                }
            }
        }
    }
}

fn collect_near_windows(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    out: &mut BTreeSet<String>,
) {
    if tokens.len() < 2 {
        return;
    }
    for left_index in 0..tokens.len() {
        let max_right = (left_index + MAX_NEAR_PATTERN_SPAN + 1).min(tokens.len());
        for right_index in left_index + 1..max_right {
            let pair = [tokens[left_index].clone(), tokens[right_index].clone()];
            if !candidate_window_is_useful(&pair, signal, profile) {
                continue;
            }
            out.insert(format!("{} {NEAR_TOKEN} {}", pair[0], pair[1]));
        }
    }
}

fn collect_quote_windows(
    tokens: &[String],
    quoted_spans: &[(usize, usize)],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    lengths: &[usize],
    out: &mut BTreeSet<String>,
) {
    for (start, end) in quoted_spans {
        if *end <= *start || *end > tokens.len() {
            continue;
        }
        let segment = &tokens[*start..*end];
        for &width in lengths {
            if width > segment.len() {
                continue;
            }
            for window in segment.windows(width) {
                if candidate_window_is_useful(window, signal, profile) {
                    out.insert(format!("{QUOTED_TOKEN} {}", window.join(" ")));
                }
            }
        }
    }
}

fn collect_conjunction_windows(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
    out: &mut BTreeSet<String>,
) {
    let anchors = signal_anchor_positions(tokens, signal, profile);
    if anchors.len() < 2 {
        return;
    }
    for left_index in 0..anchors.len() {
        let (left_pos, left_token) = &anchors[left_index];
        for (right_pos, right_token) in anchors.iter().skip(left_index + 1) {
            if *right_pos - *left_pos > MAX_CONJUNCTION_SPAN || left_token == right_token {
                continue;
            }
            out.insert(format!("{left_token} {AND_TOKEN} {right_token}"));
        }
    }
}

pub fn matching_candidate_indexes(prompt: &str, candidates: &[String]) -> Vec<usize> {
    let compiled_prompt = compile_phrase_match_text(prompt);
    let compiled_candidates: Vec<CompiledPhraseMatchText> = candidates
        .iter()
        .map(|candidate| compile_phrase_match_text(candidate))
        .collect();
    matching_candidate_indexes_compiled(&compiled_prompt, &compiled_candidates)
}

fn matching_candidate_indexes_compiled(
    prompt: &CompiledPhraseMatchText,
    candidates: &[CompiledPhraseMatchText],
) -> Vec<usize> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(index, phrase)| {
            compiled_prompt_matches_phrase(prompt, phrase).then_some(index)
        })
        .collect()
}

pub(crate) fn build_candidate_pool(
    profile: &SignalProfile,
    signal: GuardrailsSignal,
    positive_prompts: &[String],
    negative_prompts: &[String],
    max_candidates: usize,
) -> CandidatePool {
    let candidates: Vec<String> =
        rank_phrase_candidates(profile, signal, positive_prompts, negative_prompts)
            .into_iter()
            .take(max_candidates)
            .map(|(phrase, _, _)| phrase)
            .collect();
    let compiled_candidates: Vec<CompiledPhraseMatchText> = candidates
        .iter()
        .map(|candidate| compile_phrase_match_text(candidate))
        .collect();
    let positive_constraints = build_constraints(positive_prompts, &compiled_candidates);
    let negative_constraints = build_constraints(negative_prompts, &compiled_candidates);
    CandidatePool {
        candidates,
        positive_constraints,
        negative_constraints,
    }
}

fn build_constraints(
    prompts: &[String],
    compiled_candidates: &[CompiledPhraseMatchText],
) -> Vec<Vec<usize>> {
    prompts
        .iter()
        .map(|prompt| {
            let compiled_prompt = compile_phrase_match_text(prompt);
            matching_candidate_indexes_compiled(&compiled_prompt, compiled_candidates)
        })
        .filter(|matches| !matches.is_empty())
        .collect()
}

pub(crate) fn truncate_constraints(
    constraints: &[Vec<usize>],
    candidate_count: usize,
) -> Vec<Vec<usize>> {
    constraints
        .iter()
        .map(|matches| {
            matches
                .iter()
                .copied()
                .take_while(|index| *index < candidate_count)
                .collect::<Vec<_>>()
        })
        .filter(|matches| !matches.is_empty())
        .collect()
}

fn tokenize_with_structure(prompt: &str) -> (Vec<String>, Vec<usize>, Vec<(usize, usize)>) {
    let mut tokens = Vec::new();
    let mut delimiter_boundaries = Vec::new();
    let mut quoted_spans = Vec::new();
    let mut open_quote_start = None;
    let mut current = String::new();
    for ch in prompt.chars() {
        if let Some(mapped) = normalized_candidate_char(ch) {
            current.push(mapped);
        } else if !current.is_empty() {
            tokens.push(compact_candidate_token(&current));
            current.clear();
            if is_delimiter_char(ch) && delimiter_boundaries.last().copied() != Some(tokens.len()) {
                delimiter_boundaries.push(tokens.len());
            }
            if is_quote_char(ch) {
                update_quote_state(&mut open_quote_start, &mut quoted_spans, tokens.len());
            }
        } else if is_delimiter_char(ch)
            && delimiter_boundaries.last().copied() != Some(tokens.len())
        {
            delimiter_boundaries.push(tokens.len());
        } else if is_quote_char(ch) {
            update_quote_state(&mut open_quote_start, &mut quoted_spans, tokens.len());
        }
    }
    if !current.is_empty() {
        tokens.push(compact_candidate_token(&current));
    }
    (tokens, delimiter_boundaries, quoted_spans)
}

fn content_tokens(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| !compression_stopwords().contains(&token.as_str()))
        .cloned()
        .collect()
}

fn normalized_candidate_char(ch: char) -> Option<char> {
    match fold_confusable_char(ch) {
        '@' | '4' => Some('a'),
        '$' | '5' => Some('s'),
        '0' => Some('o'),
        '1' | '!' => Some('i'),
        '3' => Some('e'),
        '7' => Some('t'),
        c if c.is_ascii_alphanumeric() => Some(c),
        _ => None,
    }
}

fn is_delimiter_char(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\r' | ':' | ';' | '|' | '#' | '>' | '.' | '!' | '?' | '[' | ']' | '{' | '}'
    )
}

fn is_quote_char(ch: char) -> bool {
    matches!(ch, '"' | '`' | '“' | '”' | '‘' | '’')
}

fn compact_candidate_token(token: &str) -> String {
    let mut compacted = String::with_capacity(token.len());
    let mut previous = None;
    let mut run_length = 0usize;
    for ch in token.chars() {
        if Some(ch) == previous {
            run_length += 1;
            if run_length <= 2 {
                compacted.push(ch);
            }
        } else {
            previous = Some(ch);
            run_length = 1;
            compacted.push(ch);
        }
    }
    compacted
}

fn fold_confusable_char(ch: char) -> char {
    match ch {
        '\u{0391}' | '\u{03B1}' | '\u{0410}' | '\u{0430}' | '\u{FF41}' | '\u{FF21}' => 'a',
        '\u{0395}' | '\u{03B5}' | '\u{0415}' | '\u{0435}' | '\u{FF45}' | '\u{FF25}' => 'e',
        '\u{039F}' | '\u{03BF}' | '\u{041E}' | '\u{043E}' | '\u{FF4F}' | '\u{FF2F}' => 'o',
        '\u{03A1}' | '\u{03C1}' | '\u{0420}' | '\u{0440}' | '\u{FF50}' | '\u{FF30}' => 'p',
        '\u{03A7}' | '\u{03C7}' | '\u{0425}' | '\u{0445}' | '\u{FF58}' | '\u{FF38}' => 'x',
        '\u{03A5}' | '\u{03C5}' | '\u{0423}' | '\u{0443}' | '\u{FF59}' | '\u{FF39}' => 'y',
        '\u{03A4}' | '\u{03C4}' | '\u{0422}' | '\u{0442}' | '\u{FF54}' | '\u{FF34}' => 't',
        '\u{039A}' | '\u{03BA}' | '\u{041A}' | '\u{043A}' | '\u{FF4B}' | '\u{FF2B}' => 'k',
        '\u{039C}' | '\u{03BC}' | '\u{041C}' | '\u{043C}' | '\u{FF4D}' | '\u{FF2D}' => 'm',
        '\u{039D}' | '\u{03BD}' | '\u{041D}' | '\u{043D}' | '\u{FF48}' | '\u{FF28}' => 'h',
        '\u{03A3}' | '\u{03C3}' | '\u{0441}' | '\u{0421}' | '\u{FF43}' | '\u{FF23}' => 'c',
        _ => ch.to_ascii_lowercase(),
    }
}

fn merge_fragmented_token_runs(tokens: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        if let Some((next_index, combined)) = combined_fragmented_run(tokens, index) {
            merged.push(combined);
            index = next_index;
        } else {
            merged.push(tokens[index].clone());
            index += 1;
        }
    }
    merged
}

fn combined_fragmented_run(tokens: &[String], start: usize) -> Option<(usize, String)> {
    combined_single_char_run(tokens, start).or_else(|| combined_split_word_run(tokens, start))
}

fn combined_single_char_run(tokens: &[String], start: usize) -> Option<(usize, String)> {
    let mut end = start;
    let mut combined = String::new();
    while end < tokens.len()
        && tokens[end].chars().all(|ch| ch.is_ascii_alphabetic())
        && tokens[end].len() == 1
    {
        combined.push_str(&tokens[end]);
        end += 1;
    }
    (end >= start + 4 && combined.len() >= 6).then_some((end, combined))
}

fn combined_split_word_run(tokens: &[String], start: usize) -> Option<(usize, String)> {
    for width in [3usize, 2usize] {
        if start + width > tokens.len() {
            continue;
        }
        let window = &tokens[start..start + width];
        if window
            .iter()
            .all(|token| token.chars().all(|ch| ch.is_ascii_alphabetic()))
            && window.iter().all(|token| (2..=4).contains(&token.len()))
            && window
                .iter()
                .all(|token| !fragment_merge_stopwords().contains(&token.as_str()))
        {
            let combined = window.join("");
            if combined.len() >= 6 {
                return Some((start + width, combined));
            }
        }
    }
    None
}

fn fragment_merge_stopwords() -> [&'static str; 12] {
    [
        "a", "an", "and", "for", "how", "its", "not", "now", "the", "this", "that", "why",
    ]
}

fn update_quote_state(
    open_quote_start: &mut Option<usize>,
    quoted_spans: &mut Vec<(usize, usize)>,
    token_index: usize,
) {
    if let Some(start) = open_quote_start.take() {
        if start < token_index {
            quoted_spans.push((start, token_index));
        }
    } else {
        *open_quote_start = Some(token_index);
    }
}

fn compression_stopwords() -> [&'static str; 14] {
    [
        "a", "all", "an", "and", "any", "for", "me", "of", "please", "some", "tell", "the", "this",
        "to",
    ]
}

fn candidate_window_is_useful(
    window: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
) -> bool {
    if window.is_empty() {
        return false;
    }
    let stopwords = [
        "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is", "are", "was",
        "were", "be", "by", "as", "at", "it", "this", "that", "what", "how", "why", "who", "when",
        "where", "tell", "me", "your",
    ];
    if window
        .iter()
        .all(|token| stopwords.contains(&token.as_str()))
    {
        return false;
    }
    if window.len() == 1 && window[0].len() < 6 {
        return false;
    }
    let edge_stopwords = [
        "the", "a", "an", "this", "that", "these", "those", "my", "your", "our", "their", "his",
        "her", "its", "some", "any",
    ];
    if edge_stopwords.contains(&window[0].as_str())
        || edge_stopwords.contains(&window[window.len() - 1].as_str())
    {
        return false;
    }
    signal_window_is_useful(window, signal, profile)
}

fn signal_window_is_useful(
    window: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
) -> bool {
    let vocabulary = profile.cue_vocabulary(signal);
    match signal {
        GuardrailsSignal::InstructionOverride => {
            contains_any_token(window, vocabulary.action_tokens)
                && contains_any_token(window, vocabulary.target_tokens)
        }
        GuardrailsSignal::SystemPrompt => {
            contains_any_token(window, vocabulary.action_tokens)
                && contains_any_token(window, vocabulary.target_tokens)
        }
        GuardrailsSignal::SecretExfiltration => {
            contains_any_token(window, vocabulary.direct_tokens)
        }
        GuardrailsSignal::ToolMisuse => {
            let has_verb = contains_any_token(window, vocabulary.action_tokens);
            let has_target = contains_any_token(window, vocabulary.target_tokens);
            let has_tool = contains_any_token(window, vocabulary.tool_tokens);
            (has_verb && (has_target || has_tool)) || (has_tool && has_target)
        }
        GuardrailsSignal::DataAccessOutsideScope => {
            contains_any_token(window, vocabulary.scope_tokens)
                && contains_any_token(window, vocabulary.target_tokens)
        }
        GuardrailsSignal::IndirectDocumentAuthority => {
            contains_any_token(window, vocabulary.source_tokens)
                && contains_any_token(window, vocabulary.action_tokens)
        }
        GuardrailsSignal::BenignQuestion => contains_any_token(window, vocabulary.direct_tokens),
    }
}

fn contains_any_token(window: &[String], tokens: &[&str]) -> bool {
    window.iter().any(|token| tokens.contains(&token.as_str()))
}

fn signal_anchor_positions(
    tokens: &[String],
    signal: GuardrailsSignal,
    profile: &SignalProfile,
) -> Vec<(usize, String)> {
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| signal_anchor_token(token, signal, profile))
        .map(|(index, token)| (index, token.clone()))
        .collect()
}

fn signal_anchor_token(token: &str, signal: GuardrailsSignal, profile: &SignalProfile) -> bool {
    let vocabulary = profile.cue_vocabulary(signal);
    match signal {
        GuardrailsSignal::InstructionOverride => {
            vocabulary.action_tokens.contains(&token) || vocabulary.target_tokens.contains(&token)
        }
        GuardrailsSignal::SystemPrompt => {
            vocabulary.action_tokens.contains(&token) || vocabulary.target_tokens.contains(&token)
        }
        GuardrailsSignal::SecretExfiltration => vocabulary.direct_tokens.contains(&token),
        GuardrailsSignal::ToolMisuse => {
            vocabulary.action_tokens.contains(&token) || vocabulary.target_tokens.contains(&token)
        }
        GuardrailsSignal::DataAccessOutsideScope => {
            vocabulary.scope_tokens.contains(&token) || vocabulary.target_tokens.contains(&token)
        }
        GuardrailsSignal::IndirectDocumentAuthority => {
            vocabulary.source_tokens.contains(&token) || vocabulary.action_tokens.contains(&token)
        }
        GuardrailsSignal::BenignQuestion => vocabulary.direct_tokens.contains(&token),
    }
}
