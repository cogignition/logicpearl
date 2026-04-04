from __future__ import annotations

import os
from pathlib import Path


_PRODUCT_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_LOGICPEARL_ROOT = Path.home() / 'Documents' / 'LogicPearl'
_BCBSMA_LAYOUT = {
    'pdfs': ('raw', 'pdfs'),
    'text': ('extracted', 'text'),
    'manifests': ('processed', 'manifests'),
    'sections': ('processed', 'sections'),
    'draft_logic_specs': ('logic', 'draft_logic_specs'),
    'curated_logic_specs': ('logic', 'curated_logic_specs'),
    'final_logic_specs': ('logic', 'final_logic_specs'),
    'compiled_logic_specs': ('logic', 'compiled_logic_specs'),
    'compiled_curated_logic_specs': ('logic', 'compiled_curated_logic_specs'),
    'compiled_final_logic_specs': ('logic', 'compiled_final_logic_specs'),
    'mapping_validation': ('evaluation', 'mapping_validation'),
    'sample_cases': ('evaluation', 'sample_cases'),
    'sample_execution_results': ('evaluation', 'sample_execution_results'),
    'sample_requests': ('evaluation', 'sample_requests'),
    'sample_request_results': ('evaluation', 'sample_request_results'),
    'sample_request_audits': ('evaluation', 'sample_request_audits'),
}


def product_root() -> Path:
    return _PRODUCT_ROOT


def logicpearl_root() -> Path:
    env = os.environ.get('LOGICPEARL_ROOT')
    if env:
        return Path(env).expanduser().resolve()
    candidate = _PRODUCT_ROOT.parent
    if candidate.name == 'LogicPearl':
        return candidate
    return _DEFAULT_LOGICPEARL_ROOT


def datasets_root() -> Path:
    env = os.environ.get('LOGICPEARL_DATASETS_ROOT')
    if env:
        return Path(env).expanduser().resolve()
    return logicpearl_root() / 'datasets'


def bcbsma_medical_policies_root() -> Path:
    preferred = datasets_root() / 'public' / 'healthcare' / 'payers' / 'bcbsma' / 'medical_policies'
    if preferred.exists():
        return preferred
    return logicpearl_root() / 'research' / 'archive' / 'product_migration' / 'product_corpora_snapshot' / 'bcbsma_medical_policies'


def bcbsma_corpus_path(corpus_root: Path, logical_name: str) -> Path:
    corpus_root = corpus_root.resolve()
    mapping = _BCBSMA_LAYOUT.get(logical_name)
    if mapping is None:
        return corpus_root / logical_name
    organized = corpus_root.joinpath(*mapping)
    legacy = corpus_root / logical_name
    if organized.exists() or not legacy.exists():
        return organized
    return legacy


def bcbsma_corpus_file(corpus_root: Path, relative_path: str | Path) -> Path:
    corpus_root = corpus_root.resolve()
    relative = Path(relative_path)
    if not relative.parts:
        return corpus_root
    head, *tail = relative.parts
    base = bcbsma_corpus_path(corpus_root, head)
    return base.joinpath(*tail)
