#!/usr/bin/env python3
"""Security questionnaire responder — grounded draft + loud abstention.

Two loaders, two trust models:
  - Corpus: vendored, trusted, maximum validation (citation source).
  - Questionnaire: customer-supplied, strict documented schema or reject.

Deterministic retrieval matches each question to candidate corpus row(s).
A clear winner drafts a verbatim corpus rationale + citation; anything else
abstains as INSUFFICIENT_COVERAGE with a reason and suggested owner.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import unicodedata
from collections.abc import Hashable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent

VALID_CONFIDENCE = ("Strong", "Partial", "Contextual")

STOPWORDS = frozenset(
    {
        "a",
        "about",
        "above",
        "after",
        "again",
        "against",
        "all",
        "am",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "because",
        "been",
        "before",
        "being",
        "below",
        "between",
        "both",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "doing",
        "done",
        "down",
        "during",
        "each",
        "few",
        "for",
        "from",
        "further",
        "had",
        "has",
        "have",
        "having",
        "he",
        "her",
        "here",
        "hers",
        "herself",
        "him",
        "himself",
        "his",
        "how",
        "however",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "itself",
        "already",
        "even",
        "full",
        "including",
        "just",
        "management",
        "may",
        "me",
        "might",
        "more",
        "most",
        "must",
        "my",
        "myself",
        "new",
        "no",
        "nor",
        "not",
        "now",
        "of",
        "off",
        "on",
        "once",
        "only",
        "or",
        "other",
        "our",
        "ours",
        "ourselves",
        "out",
        "over",
        "own",
        "periodic",
        "same",
        "she",
        "should",
        "so",
        "some",
        "such",
        "than",
        "that",
        "the",
        "their",
        "theirs",
        "them",
        "themselves",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "through",
        "to",
        "too",
        "under",
        "until",
        "up",
        "very",
        "via",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "whom",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
        "yours",
        "yourself",
    }
)

# Canonical forms only — plurals normalize via TERM_EQUIVALENCE before filter.
# Includes crosswalk verbs (Decision 19) and corpus metaphor/narration tokens
# that must never score (B-A / R-4 — abstention over fabrication).
FRAMEWORK_TOKENS = frozenset(
    {
        "align",
        "angle",
        "angles",
        "annex",
        "audit",
        "auditor",
        "blend",
        "blends",
        "broad",
        "certification",
        "certified",
        "closer",
        "compliance",
        "compliant",
        "control",
        "cover",
        "criterion",
        "depth",
        "door",
        "foot",
        "frame",
        "framework",
        "get",
        "gets",
        "hop",
        "iso",
        "keep",
        "keeps",
        "loop",
        "loose",
        "map",
        "nist",
        "pivot",
        "pure",
        "rev",
        "soc",
        "tsc",
    }
)

MIN_TOKEN_LEN = 3
# Floor on raw token overlap with a corpus rationale. Below this, the row is
# not a candidate — a single shared word is ordinary English coincidence, not
# a grounded match.
GROUNDING_THRESHOLD = 2
# Floor on SECURITY_VOCABULARY overlap. Raw overlap alone can clear on filler;
# requiring two security-bearing tokens is what makes a match groundable.
MIN_SECURITY_TOKENS = 2

# Decision 21 — curated allowlist of SOC 2 control substance (canonical forms).
# Reviewed and accepted 2026-08-05. Entries annotated REVIEW are known to also
# occur in ordinary English ("system", "user", "measure"); they are kept because
# removing them breaks real access-control questions, and the resulting false
# positives are the documented known limit in the README rather than a defect to
# patch token by token. Do not derive from corpus_vocabulary().
SECURITY_VOCABULARY: frozenset[str] = frozenset(
    {
        "access",  # CC6.1 "logical access" / A.5.15 — substance
        "account",  # CC6.2 "account lifecycle" — substance
        "analyze",  # CC7.3 "reviewing and analyzing audit records" — substance
        "anomaly",  # CC7.2 "monitors ... for anomalies" — substance
        "approval",  # CC8.1 "change-approval ticket" — substance
        "approve",  # CC6.2 "approve before create" — substance
        "authentication",  # CC6.6 "authentication strength" — substance
        "authenticator",  # CC6.6 "authenticator lifecycle" — substance
        "authorization",  # CC6.1 "approved authorizations" — substance
        "authorize",  # CC6.3 "authorizes only the access" — substance
        "baseline",  # CC8.1 "baseline configuration" — substance
        "boundary",  # CC6.3 "access boundaries" — substance
        "change",  # CC8.1 "change management" — substance
        "component",  # CC7.2 "system components" — REVIEW: also generic "component type"
        "configuration",  # CC8.1 "baseline configuration" — substance
        "credential",  # CC6.2 "before credentials are issued" — substance
        "deviation",  # CC8.1 "documents deviations" — substance
        "disable",  # CC6.2 "disable, remove" — substance
        "enforce",  # CC6.1 "enforces approved authorizations" — substance
        "enforcement",  # CC6.1 "enforcement mechanisms" — substance
        "event",  # CC7.2 "event types the system can log" — substance
        "hardened",  # CC8.1 "hardened-settings state" — substance
        "identification",  # CC6.6 "unique identification" — substance
        "identity",  # CC6.2 "identity management" — REVIEW: with measure false-grounds brand-identity
        "implement",  # CC8.1 "implement changes" — substance
        "incident",  # CC7.3 "potential incidents" — substance
        "least",  # CC6.3 "least privilege" — substance
        "lifecycle",  # CC6.2 "account lifecycle" — substance
        "log",  # CC7.2 "event types the system can log" — substance
        "logical",  # CC6.1 "logical access" — substance
        "measure",  # CC6.6 "addresses measures against threats" — REVIEW: also "measure brand"
        "monitor",  # CC7.2 "monitors system components" — substance
        "policy",  # CC6.1 "from policy and technical restriction" — REVIEW: also "on-call ... policy"
        "privilege",  # CC6.3 "least privilege" — substance
        "provision",  # CC6.2 "map to provisioning" — substance
        "record",  # CC7.3 "analyzing audit records" — substance
        "registration",  # CC6.2 "registration and authorization" — substance
        "removal",  # CC6.3 "modification and removal" — substance
        "remove",  # CC6.2 "disable, remove" — substance
        # "require" omitted — with "type" false-grounds meta-1 ("Type 2" + "requirements");
        #   alone it is weak customer evidence. Luigi: add with a probe, or keep out.
        "restriction",  # CC6.1 "access restriction" — substance
        "restrictive",  # CC8.1 "restrictive configuration settings" — substance
        "revocation",  # CC6.6 "rotation, and revocation" — substance
        "risk",  # CC7.3 "when risk changes" — substance
        "role",  # CC6.3 "role-based access" — substance
        "rotation",  # CC6.6 "rotation, and revocation" — REVIEW: with policy false-grounds on-call
        "scan",  # CC8.1 "STIG or SCAP scan" — substance (AC 47 residual)
        "secure",  # CC6.6 "secure authentication" — substance
        "security",  # CC6.1 "logical-access security architecture" — substance
        "setting",  # CC8.1 "configuration settings" — substance
        "system",  # CC6.1 "at the system and application layer" — REVIEW: very common English
        "threat",  # CC6.6 "threats from outside the boundary" — substance
        # "type" omitted — "Type 2" in questionnaires + "component type" fabrication;
        #   event-type probes use event+log+system instead.
        "user",  # CC6.2 "authorization of new users" — REVIEW: generic without IAM context
    }
)

# Corpus-coupled inflection → canonical form. Unlisted tokens normalize to
# themselves — the tool never guesses at morphology. AC 7 is the coverage
# guard: a new upstream mapping row with uncovered vocabulary fails the suite
# rather than silently narrowing recall. Do not expand silently.
TERM_EQUIVALENCE: dict[str, str] = {
    # AC 3 — families revision 3 broke
    "accessed": "access",
    "accessing": "access",
    "settings": "setting",
    "issued": "issue",
    "issues": "issue",
    "issuing": "issue",
    "measures": "measure",
    "measured": "measure",
    "measuring": "measure",
    "processed": "process",
    "processes": "process",
    "based": "base",
    "roles": "role",
    "devices": "device",
    "services": "service",
    "procedures": "procedure",
    # AC 4 — prior AC-12 families (mechanism is the table, not a stemmer)
    "requires": "require",
    "required": "require",
    "requiring": "require",
    "requirements": "require",
    "reviews": "review",
    "reviewed": "review",
    "reviewing": "review",
    "accounts": "account",
    "analyzed": "analyze",
    "analyzing": "analyze",
    "analyzes": "analyze",
    # Framework/boilerplate plurals (normalize before filter — Decision 15)
    "audits": "audit",
    "auditors": "auditor",
    "certifications": "certification",
    "frameworks": "framework",
    "annexes": "annex",
    "controls": "control",
    "criteria": "criterion",
    # Corpus- and sample-coupled inflections (hand-reviewed 2026-08-04)
    "users": "user",
    "credentials": "credential",
    "systems": "system",
    "events": "event",
    "changes": "change",
    "changed": "change",
    "changing": "change",
    "addresses": "address",
    "addressed": "address",
    "addressing": "address",
    "authorizations": "authorization",
    "authorizes": "authorize",
    "authorized": "authorize",
    "authorizing": "authorize",
    "mechanisms": "mechanism",
    "maps": "map",
    "aligns": "align",
    "covers": "cover",
    "maintains": "maintain",
    "maintaining": "maintain",
    "maintained": "maintain",
    "logged": "log",
    "logging": "log",
    "logs": "log",
    "privileged": "privilege",
    "privileges": "privilege",
    "records": "record",
    "recorded": "record",
    "recording": "record",
    "boundaries": "boundary",
    "anomalies": "anomaly",
    "defined": "define",
    "defining": "define",
    "defines": "define",
    "implements": "implement",
    "implemented": "implement",
    "implementing": "implement",
    "monitors": "monitor",
    "monitoring": "monitor",
    "monitored": "monitor",
    "enforces": "enforce",
    "enforced": "enforce",
    "enforcing": "enforce",
    "documents": "document",
    "documented": "document",
    "documenting": "document",
    "frames": "frame",
    "approved": "approve",
    "approves": "approve",
    "approving": "approve",
    "provisioning": "provision",
    "provisioned": "provision",
    # Offboarding is NOT onboarding — collapsing these into "provision" made
    # deprovision questions cite CC6.2's registration rationale (G-1 polarity).
    "deprovisioned": "deprovision",
    "deprovisioning": "deprovision",
    "policies": "policy",
    "revoke": "revocation",
    "revoked": "revocation",
    "revokes": "revocation",
    # Corpus-side plurality / tense (hand-reviewed against vendored rationales)
    "types": "type",
    "tasks": "task",
    "activities": "activity",
    "components": "component",
    "deviations": "deviation",
    "findings": "finding",
    "incidents": "incident",
    "rights": "right",
    "threats": "threat",
    "duties": "duty",
    "disabled": "disable",
    "disables": "disable",
    "disabling": "disable",
    "removed": "remove",
    "removes": "remove",
    "removing": "remove",
    "modified": "modify",
    "modifies": "modify",
    "modifying": "modify",
    # Question-side plurals (M1r4 / Decision 21 recall)
    "applications": "application",
    "restrictions": "restriction",
    "layers": "layer",
    "identities": "identity",
    "baselines": "baseline",
    "configurations": "configuration",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CONTROL_ID_RE = re.compile(
    r"\b(?:cc|ac|ia|au|cm|sc|si|cp|ir|ra|pe|mp|ca|pl|ps|sa|pm|at)[-.\s]?\d+(?:\.\d+)*\b"
    r"|\ba\.\d+\.\d+\b",
    re.IGNORECASE,
)
# Zero-width separators become spaces so they split words rather than fuse them.
_ZERO_WIDTH_TO_SPACE = str.maketrans(
    {
        "\u200b": " ",  # ZERO WIDTH SPACE
        "\u200c": " ",  # ZERO WIDTH NON-JOINER
        "\u200d": " ",  # ZERO WIDTH JOINER
        "\u2060": " ",  # WORD JOINER
        "\ufeff": " ",  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)
_SOC2_CITATION_RE = re.compile(r"\bcc\s*(\d+(?:\.\d+)*)\b", re.IGNORECASE)
_ISO_CITATION_RE = re.compile(r"\ba\.(\d+\.\d+)\b", re.IGNORECASE)
_NIST_CITATION_RE = re.compile(
    r"\b(ac|ia|au|cm|sc|si|cp|ir|ra|pe|mp|ca|pl|ps|sa|pm|at)-(\d+)\b",
    re.IGNORECASE,
)

# Documented questionnaire schema — exact names only, no aliases.
CSV_ALLOWED_HEADERS = frozenset({"id", "text"})
QUESTION_ALLOWED_KEYS = frozenset({"id", "text"})

# Unicode categories that must not reach a terminal (C0/C1, bidi, zero-width).
_UNSAFE_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


@dataclass(frozen=True)
class InputPath:
    """A path argument, canonicalized once at the CLI boundary.

    ``real`` is for filesystem I/O and nothing else.
    ``display`` is for messages and nothing else.
    """

    real: Path
    display: str


def _safe_display_text(text: str) -> str:
    """Escape controls/bidi/zero-width; leave printable non-ASCII intact."""
    parts: list[str] = []
    for ch in text:
        if ch == "\t":
            parts.append(ch)
            continue
        category = unicodedata.category(ch)
        if category in _UNSAFE_UNICODE_CATEGORIES:
            code = ord(ch)
            if code <= 0xFF:
                parts.append(f"\\x{code:02x}")
            else:
                parts.append(f"\\u{code:04x}")
        else:
            parts.append(ch)
    return "".join(parts)


def input_path(raw: str) -> InputPath:
    """argparse ``type=`` callable. Computes ``display`` exactly once, here."""
    if raw == "" or raw == ".":
        return InputPath(real=Path(raw) if raw else Path(""), display="<path>")

    dir_by_syntax = raw.endswith("/") or (os.sep != "/" and raw.endswith(os.sep))
    path = Path(raw)

    try:
        cwd = Path.cwd()
    except OSError:
        # Working directory deleted — never invent a resolvable location.
        if dir_by_syntax:
            return InputPath(real=path, display="<directory>")
        name = path.name if path.name not in ("", ".", "..") else "<path>"
        return InputPath(real=path, display=_safe_display_text(name))

    try:
        resolved = path.resolve() if path.is_absolute() else (cwd / path).resolve()
        shown = resolved.relative_to(REPO_ROOT).as_posix()
        return InputPath(real=path, display=_safe_display_text(shown))
    except (ValueError, OSError):
        is_dir = dir_by_syntax
        if not is_dir:
            for candidate in (path, cwd / path if not path.is_absolute() else path):
                try:
                    if candidate.is_dir():
                        is_dir = True
                        break
                except OSError:
                    continue
        if is_dir:
            shown = "<directory>"
        else:
            shown = path.name if path.name not in ("", ".", "..") else "<path>"
        return InputPath(real=path, display=_safe_display_text(shown))


DEFAULT_CORPUS = InputPath(
    real=REPO_ROOT / "corpus" / "mappings.yaml",
    display="corpus/mappings.yaml",
)


def _coerce_input_path(path: InputPath | Path | str) -> InputPath:
    """Accept InputPath or Path/str (tests / internal callers)."""
    if isinstance(path, InputPath):
        return path
    if isinstance(path, Path):
        return input_path(os.fsdecode(os.fsencode(path)))
    return input_path(path)


def _read_text(ip: InputPath, *, encoding: str = "utf-8") -> str:
    """Read ``ip.real``; on failure raise a message that uses ``ip.display`` only."""
    try:
        return ip.real.read_text(encoding=encoding)
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise OSError(exc.errno, f"cannot read {ip.display}: {detail}") from None
    except UnicodeDecodeError as exc:
        # A decode failure is a ValueError, not an OSError, so it would escape
        # the wrapper above and reach stderr naming a byte offset but no file.
        raise ValueError(
            f"{ip.display}: not valid {encoding}: "
            f"byte 0x{exc.object[exc.start]:02x} at position {exc.start}"
        ) from None


def _yaml_load(text: str, *, source: str, loader: type[yaml.SafeLoader]) -> Any:
    """Load YAML from text with stream.name = display form (no real path in marks)."""
    stream = io.StringIO(text)
    stream.name = source
    return yaml.load(stream, Loader=loader)


def _format_cli_error(exc: BaseException, *, include_type: bool = False) -> str:
    """Format an exception for stderr. Paths must already be display forms in ``exc``."""
    if include_type:
        text = f"{type(exc).__name__}: {exc}"
    else:
        text = str(exc) if str(exc) else type(exc).__name__
    return _safe_display_text(text)


def _yaml_line(node: yaml.Node) -> int:
    return node.start_mark.line + 1


def _reject_merge_and_duplicates(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    *,
    source: str,
    deep: bool,
) -> None:
    """Shared guard for both loaders: no << merge keys, no duplicate keys."""
    for key_node, _value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise ValueError(
                f"{source}: line {_yaml_line(key_node)}: "
                "YAML merge keys (<<) are not allowed"
            )
    seen: set[Hashable] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, Hashable):
            continue
        if key in seen:
            raise ValueError(
                f"{source}: line {_yaml_line(key_node)}: duplicate key {key!r}"
            )
        seen.add(key)


def _make_corpus_loader(source: str) -> type[yaml.SafeLoader]:
    """Trusted corpus loader: reject merge keys and duplicate keys (with path)."""

    class CorpusLoader(yaml.SafeLoader):
        def construct_mapping(self, node: yaml.MappingNode, deep: bool = False):
            _reject_merge_and_duplicates(self, node, source=source, deep=deep)
            return super().construct_mapping(node, deep=deep)

    return CorpusLoader


def _make_questionnaire_loader(source: str) -> type[yaml.SafeLoader]:
    """Customer questionnaire loader: reject merge keys and duplicate keys."""

    class QuestionnaireLoader(yaml.SafeLoader):
        def construct_mapping(self, node: yaml.MappingNode, deep: bool = False):
            _reject_merge_and_duplicates(self, node, source=source, deep=deep)
            return super().construct_mapping(node, deep=deep)

    return QuestionnaireLoader


def _stable_sort_keys(keys: Any) -> list[Any]:
    """Sort keys without TypeError when types are mixed (int vs str)."""
    return sorted(keys, key=lambda k: (type(k).__name__, repr(k)))


def _validate_string_list(
    value: Any,
    index: int,
    field_name: str,
    *,
    source: str,
    allow_empty: bool = False,
) -> None:
    """Require a list of non-blank strings (ISO / NIST ref lists)."""
    where = f"{source}: mapping row {index}"
    if not isinstance(value, list):
        raise ValueError(
            f"{where}: {field_name} must be a list of strings, "
            f"got {type(value).__name__}"
        )
    if len(value) == 0:
        if allow_empty:
            return
        raise ValueError(f"{where}: blank field {field_name!r}")
    for element_index, element in enumerate(value):
        if not isinstance(element, str) or not element.strip():
            raise ValueError(
                f"{where}: {field_name}[{element_index}] must be a "
                f"non-blank string, got {element!r}"
            )


def _validate_mapping_row(row: dict, index: int, *, source: str) -> None:
    """Raise ValueError if a mapping row is missing required grounding fields."""
    required = ("soc2_cc", "iso_27001_2022", "confidence", "rationale")
    where = f"{source}: mapping row {index}"

    for field_name in required:
        if field_name not in row:
            raise ValueError(f"{where}: missing field {field_name!r}")
        value = row[field_name]
        if value is None:
            raise ValueError(f"{where}: blank field {field_name!r}")
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"{where}: blank field {field_name!r}")
        if isinstance(value, list) and len(value) == 0:
            raise ValueError(f"{where}: blank field {field_name!r}")

    for field_name in ("soc2_cc", "rationale"):
        if not isinstance(row[field_name], str):
            raise ValueError(
                f"{where}: {field_name} must be a string, "
                f"got {type(row[field_name]).__name__}"
            )

    if not isinstance(row["confidence"], str):
        raise ValueError(
            f"{where}: confidence must be a string, "
            f"got {type(row['confidence']).__name__}"
        )

    confidence = row["confidence"].strip()
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"{where}: invalid confidence {row['confidence']!r}")

    _validate_string_list(
        row["iso_27001_2022"], index, "iso_27001_2022", source=source
    )


@dataclass(frozen=True)
class MappingRow:
    """One grounded mapping from the corpus — citation source for later stages."""

    soc2_cc: str
    iso_27001_2022: tuple[str, ...]
    confidence: str
    rationale: str
    nist_800_53: tuple[str, ...] = ()
    rationale_tokens: tuple[str, ...] = ()
    # Error-context only — load_corpus stamps these so __post_init__ can name the pin.
    source: str = "MappingRow"
    row_index: int | None = None

    def _error_where(self) -> str:
        if self.row_index is None:
            return self.source
        return f"{self.source}: mapping row {self.row_index}"

    def __post_init__(self) -> None:
        # AC 21 / 37: blank rationale cannot carry a fabricated token cache.
        # Non-blank rationale that tokenizes empty is kept as a permanently
        # non-matching row (Decision: load-as-unmatchable — fails safe).
        # A caller-supplied cache must still equal tokenize(rationale).
        where = self._error_where()
        if not self.rationale.strip():
            if self.rationale_tokens:
                raise ValueError(
                    f"{where}: blank rationale cannot carry rationale_tokens"
                )
            return
        expected = tokenize(self.rationale)
        if self.rationale_tokens:
            if self.rationale_tokens != expected:
                raise ValueError(
                    f"{where}: rationale_tokens does not match tokenize(rationale)"
                )
        else:
            object.__setattr__(self, "rationale_tokens", expected)


@dataclass(frozen=True)
class Corpus:
    """In-memory control corpus. version is stamped into the JSON audit record (#4)."""

    version: str
    mappings: tuple[MappingRow, ...]
    path: InputPath


@dataclass(frozen=True)
class Question:
    """Normalized questionnaire item — format-agnostic record for retrieval."""

    id: str
    text: str
    issues: tuple[str, ...] = ()

    @property
    def display_id(self) -> str:
        """Terminal-safe id; stored ``id`` stays the customer's verbatim value."""
        return _safe_display_text(self.id)


@dataclass(frozen=True)
class RetrievalHit:
    """One candidate corpus row for a question. A hit is not a verdict."""

    row: MappingRow
    score: int
    matched_tokens: tuple[str, ...]


@dataclass(frozen=True)
class RetrievalResult:
    """Outcome of retrieval. Zero, one, or several tied candidates.

    hits is ordered by corpus index and carries every row tied at the top score.
    len(hits) > 1 is the ambiguity signal decide() routes to abstention
    (cross-criterion) or corpus-order pick (same-criterion).
    """

    hits: tuple[RetrievalHit, ...]

    @property
    def is_empty(self) -> bool:
        return len(self.hits) == 0

    @property
    def is_ambiguous(self) -> bool:
        return len(self.hits) > 1


def normalize_token(token: str) -> str:
    """Map one lowercase token to its canonical form, or itself if unlisted."""
    return TERM_EQUIVALENCE.get(token, token)


def corpus_vocabulary(corpus: Corpus) -> frozenset[str]:
    """Every canonical content token reachable from loaded corpus rationales."""
    vocab: set[str] = set()
    for row in corpus.mappings:
        vocab.update(row.rationale_tokens)
    return frozenset(vocab)


def cited_row_ids(text: str) -> frozenset[str]:
    """Control IDs named in the question, normalised (CC6.1, A.8.15, AC-3)."""
    found: set[str] = set()
    for match in _SOC2_CITATION_RE.finditer(text):
        found.add(f"CC{match.group(1)}")
    for match in _ISO_CITATION_RE.finditer(text):
        found.add(f"A.{match.group(1)}")
    for match in _NIST_CITATION_RE.finditer(text):
        found.add(f"{match.group(1).upper()}-{match.group(2)}")
    return frozenset(found)


def tokenize(text: str) -> tuple[str, ...]:
    """Content tokens via the locked pipeline (zero-width→space through filter).

    STOPWORDS / FRAMEWORK_TOKENS / MIN_TOKEN_LEN / isdigit apply to questions and
    rationales alike (Decision 17 — one shared filter path).
    """
    # 1. Zero-width separators → space (do not fuse least‌privilege).
    spaced = text.translate(_ZERO_WIDTH_TO_SPACE)
    # 2. Strip remaining Cf only — never Cc (YAML newlines must survive).
    stripped = "".join(ch for ch in spaced if unicodedata.category(ch) != "Cf")
    # 3. NFKC — ligatures / fullwidth.
    normalized = unicodedata.normalize("NFKC", stripped)
    # 4. Accent-fold: NFD, drop Mn, recompose.
    nfd = unicodedata.normalize("NFD", normalized)
    folded = "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")
    folded = unicodedata.normalize("NFC", folded)
    # 5. Strip control-ID-shaped substrings from prose.
    deidentified = _CONTROL_ID_RE.sub(" ", folded)
    # 6–8. Lowercase split → normalize → filter (Decision 15: normalize first).
    tokens: list[str] = []
    for token in _TOKEN_RE.findall(deidentified.lower()):
        canonical = normalize_token(token)
        if canonical in STOPWORDS:
            continue
        if canonical in FRAMEWORK_TOKENS:
            continue
        if len(canonical) < MIN_TOKEN_LEN:
            continue
        if canonical.isdigit():
            continue
        tokens.append(canonical)
    return tuple(tokens)


def _score_token_sets(
    question_tokens: set[str], row: MappingRow
) -> tuple[int, tuple[str, ...], int]:
    """Overlap, matched tokens (sorted), and security-bearing match count."""
    if not question_tokens:
        return 0, (), 0
    row_tokens = set(row.rationale_tokens)
    matched = sorted(question_tokens & row_tokens)
    security_count = sum(1 for token in matched if token in SECURITY_VOCABULARY)
    return len(matched), tuple(matched), security_count


def score_question_against_row(
    question: Question, row: MappingRow
) -> tuple[int, tuple[str, ...], int]:
    """Token overlap between question text and one corpus row's rationale."""
    return _score_token_sets(set(tokenize(question.text)), row)


def retrieve(question: Question, corpus: Corpus) -> RetrievalResult:
    """All rows tied at the highest score meeting the grounding gates.

    A row must clear GROUNDING_THRESHOLD on raw overlap and MIN_SECURITY_TOKENS
    on security-bearing overlap (Decision 21). Confidence never selects here;
    same-criterion ties resolve to corpus order via decide()->_pick_hit.
    """
    question_tokens = set(tokenize(question.text))
    if not question_tokens:
        return RetrievalResult(hits=())

    scored: list[tuple[int, RetrievalHit]] = []
    for index, row in enumerate(corpus.mappings):
        score, matched, security_count = _score_token_sets(question_tokens, row)
        if score < GROUNDING_THRESHOLD:
            continue
        if security_count < MIN_SECURITY_TOKENS:
            continue
        scored.append(
            (index, RetrievalHit(row=row, score=score, matched_tokens=matched))
        )

    if not scored:
        return RetrievalResult(hits=())

    top_score = max(hit.score for _, hit in scored)
    tied = [(index, hit) for index, hit in scored if hit.score == top_score]
    tied.sort(key=lambda item: item[0])
    return RetrievalResult(hits=tuple(hit for _, hit in tied))


# Demo-tuned (not derived): produce a mix of answers and abstentions on the
# sample questionnaire. retrieve() gates on GROUNDING_THRESHOLD; build_record()
# applies MARGIN over the runner-up on top.
# Required gap between the top hit and the best other-criterion runner-up.
# Gap < MARGIN means the tool cannot tell which criterion wins — abstain so a
# human adjudicates (Decision 1). Value 2.0 matches the sample mix (2/6).
MARGIN = 2.0

OWNERS = {
    "access": "Identity & Access Management",
    "authentication": "Identity & Access Management",
    "privilege": "Identity & Access Management",
    "account": "Identity & Access Management",
    "monitor": "Security Operations",
    "incident": "Security Operations",
    "change": "Change Management",
    "residency": "Privacy / Legal",
}
DEFAULT_OWNER = "Security SME (unrouted)"

DEFAULT_OUT_DIR = InputPath(real=REPO_ROOT / "drafts", display="drafts")


def _coverage_pct(answered: int, total: int) -> int:
    """Floor percent — never report 100% while any question abstained."""
    if total == 0:
        return 0
    return (100 * answered) // total


def _md_prose(text: str) -> str:
    """Neutralize Markdown/HTML structure in customer-supplied text (B5/B2)."""
    if not text:
        return "(blank)"
    flat = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ")
    escaped = (
        flat.replace("\\", "\\\\")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("#", "\\#")
        .replace("`", "\\`")
        .replace("[", "\\[")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
    )
    return _safe_display_text(escaped)


def _row_label(row: MappingRow) -> str:
    """Human-facing row id: criterion plus confidence and NIST anchor."""
    nist = ",".join(row.nist_800_53) if row.nist_800_53 else "no-nist"
    return f"{row.soc2_cc} ({row.confidence}, {nist})"


def _pick_hit(hits: tuple[RetrievalHit, ...]) -> RetrievalHit:
    """First hit in corpus order.

    No tier is computed or upgraded — the confidence on an answered record is
    copied from the row that matched. When several rows of the SAME criterion
    tie, the earliest corpus row wins; the crosswalk authors each criterion
    strongest-mapping-first, so that is the strongest tied tier. Known limit:
    a tied weaker facet of the same criterion is not surfaced.
    """
    return hits[0]


def suggest_owner(question: Question) -> str:
    """Route an abstention via tokenized keyword match (longest wins)."""
    tokens = set(tokenize(question.text))
    matches: list[tuple[int, str]] = []
    for keyword, owner in OWNERS.items():
        if keyword in tokens:
            matches.append((len(keyword), owner))
    if not matches:
        return DEFAULT_OWNER
    matches.sort(reverse=True)
    return matches[0][1]


def _abstain_record(question: Question, reason: str) -> dict:
    return {
        "question_id": question.id,
        "question_text": question.text,
        "status": "INSUFFICIENT_COVERAGE",
        "answer": None,
        "criterion": "",
        "confidence": "",
        "rationale": "",
        "iso_27001_2022": "",
        "nist_800_53": "",
        "owner": suggest_owner(question),
        "reason": reason,
    }


def decide(result: RetrievalResult) -> tuple[str, object]:
    """Map a retrieval result to answered hit or abstention reason.

    Returns ("answered", RetrievalHit) or ("abstained", reason_str).
    Same-criterion ties resolve to corpus order (confidence is never a
    tiebreak). Cross-criterion ties abstain. Near-ties are handled in
    build_record via margin.
    """
    if result.is_empty:
        return ("abstained", "no grounded corpus match")
    if result.is_ambiguous:
        criteria: list[str] = []
        for hit in result.hits:
            if hit.row.soc2_cc not in criteria:
                criteria.append(hit.row.soc2_cc)
        if len(criteria) == 1:
            return ("answered", _pick_hit(result.hits))
        labels: list[str] = []
        seen: list[str] = []
        for hit in result.hits:
            if hit.row.soc2_cc in seen:
                continue
            seen.append(hit.row.soc2_cc)
            labels.append(_row_label(hit.row))
        return ("abstained", "top hits within MARGIN: " + " vs ".join(labels))
    return ("answered", result.hits[0])


def draft_answer(question: Question, hit: RetrievalHit, corpus: Corpus) -> dict:
    """Build an answered record: corpus rationale verbatim + inherited confidence."""
    row = hit.row
    return {
        "question_id": question.id,
        "question_text": question.text,
        "status": "answered",
        # answer IS the corpus rationale (Decision 2) — same string as rationale
        # so abstentions can carry an explicit null without a second body field.
        "answer": row.rationale,
        "criterion": row.soc2_cc,
        "confidence": row.confidence,
        "rationale": row.rationale,
        "iso_27001_2022": list(row.iso_27001_2022),
        "nist_800_53": list(row.nist_800_53),
        "owner": "",
        "reason": "",
    }


def _runner_up(
    question: Question,
    top: MappingRow,
    corpus: Corpus,
    retrieved: tuple[RetrievalHit, ...],
) -> tuple[MappingRow | None, float]:
    """Best-scoring row not returned by retrieve(), different soc2_cc than top.

    Decision 1 compares the top retrieved score to this runner-up; gap < MARGIN
    abstains. Same-criterion facets are not competitors (B3).
    """
    retrieved_rows = {hit.row for hit in retrieved}
    question_tokens = set(tokenize(question.text))
    best_row: MappingRow | None = None
    best_score = -1.0
    for row in corpus.mappings:
        if row in retrieved_rows:
            continue
        if row.soc2_cc == top.soc2_cc:
            continue
        score, _matched, security_count = _score_token_sets(question_tokens, row)
        if score < GROUNDING_THRESHOLD:
            continue
        if security_count < MIN_SECURITY_TOKENS:
            continue
        if float(score) > best_score:
            best_score = float(score)
            best_row = row
    return best_row, best_score


def build_record(question: Question, corpus: Corpus) -> dict:
    """Retrieve, decide (MARGIN over runner-up), draft or abstain."""
    if not question.text.strip():
        return _abstain_record(question, "blank question text")
    result = retrieve(question, corpus)
    status, payload = decide(result)
    if status == "abstained":
        return _abstain_record(question, str(payload))

    hit = payload  # RetrievalHit
    runner, runner_score = _runner_up(question, hit.row, corpus, result.hits)
    if runner is not None and (float(hit.score) - runner_score) < MARGIN:
        reason = (
            "top hits within MARGIN: "
            f"{_row_label(hit.row)} vs {_row_label(runner)}"
        )
        return _abstain_record(question, reason)
    return draft_answer(question, hit, corpus)


def render_markdown(records: list[dict], corpus: Corpus) -> str:
    """Reviewer-facing Markdown draft (deterministic, diffable)."""
    answered = sum(1 for record in records if record["status"] == "answered")
    total = len(records)
    pct = _coverage_pct(answered, total)
    lines = [
        "# Questionnaire responses",
        "",
        f"Corpus: {corpus.path.display} (version {corpus.version})",
        f"Coverage: {answered}/{total} ({pct}%)",
        "",
    ]
    for record in records:
        lines.append(f"### {_md_prose(record['question_id'])}")
        lines.append("")
        lines.append(_md_prose(record["question_text"]))
        lines.append("")
        if record["status"] == "answered":
            lines.append("**Status:** answered")
            lines.append("")
            lines.append(f"**Criterion:** SOC 2 {record['criterion']}")
            lines.append("")
            iso = ", ".join(record["iso_27001_2022"])
            nist = ", ".join(record["nist_800_53"]) if record["nist_800_53"] else "—"
            lines.append(
                f"**Cross-references:** ISO 27001:2022 {iso}; NIST 800-53 {nist}"
            )
            lines.append("")
            lines.append(f"**Confidence:** {record['confidence']}")
            lines.append("")
            lines.append(f"**Rationale:** {record['rationale']}")
            lines.append("")
            lines.append(
                f"**Source:** {corpus.path.display} version {corpus.version}"
            )
        else:
            lines.append("**Status:** INSUFFICIENT_COVERAGE")
            lines.append("")
            lines.append(f"**Reason:** {_md_prose(record['reason'])}")
            lines.append("")
            lines.append(f"**Suggested owner:** {_md_prose(record['owner'])}")
        lines.append("")
    return "\n".join(lines)


def render_json(records: list[dict], corpus: Corpus) -> str:
    """JSON audit record: corpus stamp + the response list."""
    answered = sum(1 for record in records if record["status"] == "answered")
    payload = {
        "corpus_version": corpus.version,
        "corpus": corpus.path.display,
        "answered": answered,
        "total": len(records),
        "responses": records,
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


@dataclass
class Questionnaire:
    """Parsed questionnaire plus any row-level problems reported (not dropped)."""

    path: InputPath
    questions: list[Question] = field(default_factory=list)


def load_corpus(path: InputPath | Path | str | None = None) -> Corpus:
    """Load the trusted vendored corpus. Fail loudly — never load partially.

    --corpus is trusted-input-only: point it at another reviewed pin, not at
    arbitrary customer YAML.
    """
    ip = DEFAULT_CORPUS if path is None else _coerce_input_path(path)
    source = ip.display
    try:
        is_file = ip.real.is_file()
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise OSError(exc.errno, f"cannot access {source}: {detail}") from None
    if not is_file:
        raise FileNotFoundError(f"corpus not found: {source}")

    text = _read_text(ip, encoding="utf-8")
    raw = _yaml_load(text, source=source, loader=_make_corpus_loader(source))

    if not isinstance(raw, dict):
        raise ValueError(
            f"{source}: corpus root must be a mapping, got {type(raw).__name__}"
        )

    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"{source}: corpus missing metadata mapping")

    version = metadata.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError(
            f"{source}: metadata.version must be a non-blank string "
            f"(quote it in YAML), got {version!r}"
        )
    version = version.strip()

    if "row_count" not in metadata:
        raise ValueError(f"{source}: metadata.row_count is required")
    row_count = metadata["row_count"]
    if isinstance(row_count, bool) or not isinstance(row_count, int):
        raise ValueError(
            f"{source}: metadata.row_count must be an int, got {row_count!r} "
            f"({type(row_count).__name__})"
        )

    rows_raw = raw.get("mappings")
    if not isinstance(rows_raw, list) or len(rows_raw) == 0:
        raise ValueError(f"{source}: mappings must be a non-empty list")

    mappings: list[MappingRow] = []
    for index, row in enumerate(rows_raw):
        if not isinstance(row, dict):
            raise ValueError(
                f"{source}: mapping row {index}: expected a mapping, "
                f"got {type(row).__name__}"
            )
        _validate_mapping_row(row, index, source=source)

        if "nist_800_53" not in row or row["nist_800_53"] is None:
            nist: list[Any] = []
        else:
            nist = row["nist_800_53"]
            _validate_string_list(
                nist, index, "nist_800_53", source=source, allow_empty=True
            )

        rationale = row["rationale"].strip()
        mappings.append(
            MappingRow(
                soc2_cc=row["soc2_cc"].strip(),
                iso_27001_2022=tuple(item.strip() for item in row["iso_27001_2022"]),
                confidence=row["confidence"].strip(),
                rationale=rationale,
                nist_800_53=tuple(item.strip() for item in nist),
                rationale_tokens=tokenize(rationale),
                source=source,
                row_index=index,
            )
        )

    if row_count != len(mappings):
        raise ValueError(
            f"{source}: metadata.row_count is {row_count} but loaded "
            f"{len(mappings)} mapping rows"
        )

    return Corpus(version=version, mappings=tuple(mappings), path=ip)


def check_questionnaire_schema(data: object, *, source: str) -> list[dict[str, Any]]:
    """Validate questionnaire YAML against the strict schema; return item dicts.

    Schema:
      - Root mapping with exact key ``questions`` (no ``items``, no aliases).
      - ``questions`` is a non-empty list.
      - Uniform items: all bare strings, or all mappings.
      - Mappings allow only ``id`` (optional string) and ``text`` (required string).
      - Blank ``text`` is allowed here and flagged later — missing ``text`` is not.

    Raises ValueError with ``{source}: ...`` (and line when available from loader).
    """
    if not isinstance(data, dict):
        raise ValueError(
            f"{source}: questionnaire root must be a mapping with a 'questions' key, "
            f"got {type(data).__name__}"
        )

    if "questions" not in data:
        raise ValueError(f"{source}: missing required root key 'questions'")

    unknown_root = _stable_sort_keys(set(data) - {"questions"})
    if unknown_root:
        raise ValueError(
            f"{source}: unexpected root key(s) {unknown_root}; "
            "only 'questions' is allowed"
        )

    items = data["questions"]
    if items is None:
        raise ValueError(f"{source}: 'questions' is null; expected a non-empty list")
    if not isinstance(items, list):
        raise ValueError(
            f"{source}: 'questions' must be a list, got {type(items).__name__}"
        )
    if len(items) == 0:
        raise ValueError(f"{source}: 'questions' must be a non-empty list")

    if all(isinstance(item, str) for item in items):
        return [{"text": item} for item in items]

    if all(isinstance(item, dict) for item in items):
        normalized: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            unknown = _stable_sort_keys(set(item) - QUESTION_ALLOWED_KEYS)
            if unknown:
                raise ValueError(
                    f"{source}: question {index + 1}: unexpected key(s) {unknown}; "
                    "only 'id' and 'text' are allowed"
                )
            if "text" not in item:
                raise ValueError(
                    f"{source}: question {index + 1}: missing required key 'text'"
                )
            text = item["text"]
            if text is not None and not isinstance(text, str):
                raise ValueError(
                    f"{source}: question {index + 1}: 'text' must be a string "
                    f"(quote the value in YAML), got {type(text).__name__}"
                )
            if "id" in item and item["id"] is not None and not isinstance(item["id"], str):
                raise ValueError(
                    f"{source}: question {index + 1}: 'id' must be a string "
                    f"(quote the value in YAML), got {type(item['id']).__name__}"
                )
            entry: dict[str, Any] = {"text": "" if text is None else text}
            if "id" in item and item["id"] is not None:
                entry["id"] = item["id"]
            normalized.append(entry)
        return normalized

    kinds = sorted({type(item).__name__ for item in items})
    if len(kinds) == 1:
        raise ValueError(
            f"{source}: 'questions' items must be strings or mappings, "
            f"got {kinds[0]}"
        )
    raise ValueError(
        f"{source}: 'questions' must be all strings or all mappings, "
        f"got mixed types {kinds}"
    )


def _question_from_fields(
    raw_id: str | None,
    raw_text: str | None,
    index: int,
) -> Question:
    """Build a Question; blank text and substituted IDs are flags, not hard errors.

    ``index`` is the 0-based list position for YAML, or ``line_no - 1`` for CSV
    so ``_auto_N`` matches the 1-indexed file line (including the header).
    Customer ids are stored verbatim; use ``Question.display_id`` at print sites.
    """
    issues: list[str] = []

    if raw_id is None or not raw_id.strip():
        qid = f"_auto_{index + 1}"
        issues.append("substituted question id")
    else:
        qid = raw_id.strip()

    if raw_text is None or not raw_text.strip():
        text = ""
        issues.append("blank question text")
    else:
        text = raw_text.strip()

    return Question(id=qid, text=text, issues=tuple(issues))


def _parse_questionnaire_yaml(ip: InputPath) -> list[Question]:
    source = ip.display
    text = _read_text(ip, encoding="utf-8")
    raw = _yaml_load(text, source=source, loader=_make_questionnaire_loader(source))

    items = check_questionnaire_schema(raw, source=source)
    return [
        _question_from_fields(item.get("id"), item.get("text"), index)
        for index, item in enumerate(items)
    ]


def _parse_questionnaire_csv(ip: InputPath) -> list[Question]:
    """Strict CSV: headers are exactly id and/or text; rows are rectangular."""
    source = ip.display
    # utf-8-sig strips a leading BOM so Excel-exported files still match.
    try:
        handle = ip.real.open(encoding="utf-8-sig", newline="")
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise OSError(exc.errno, f"cannot read {source}: {detail}") from None
    with handle:
        reader = csv.reader(handle)
        try:
            rows = list(reader)
        except csv.Error as exc:
            # csv.Error is raised mid-iteration, outside the open() wrapper above.
            raise ValueError(f"{source}: line {reader.line_num}: {exc}") from None
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"{source}: line {reader.line_num}: not valid utf-8: "
                f"byte 0x{exc.object[exc.start]:02x} at position {exc.start}"
            ) from None
        except OSError as exc:
            detail = exc.strerror or type(exc).__name__
            raise OSError(exc.errno, f"cannot read {source}: {detail}") from None

    if not rows:
        raise ValueError(f"{source}: CSV is empty")

    # Row numbers are 1-indexed including the header line.
    header = rows[0]
    if not header:
        raise ValueError(f"{source}: line 1: CSV has no header row")

    for col_index, name in enumerate(header):
        if name is None or not str(name).strip():
            raise ValueError(
                f"{source}: line 1: blank header in column {col_index + 1}"
            )

    headers = [name.strip() for name in header]
    if len(headers) != len(set(headers)):
        raise ValueError(f"{source}: line 1: duplicate CSV header(s) in {headers}")

    unknown = sorted(set(headers) - CSV_ALLOWED_HEADERS)
    if unknown:
        raise ValueError(
            f"{source}: line 1: unexpected CSV header(s) {unknown}; "
            "only 'id' and 'text' are allowed"
        )
    if "text" not in headers:
        raise ValueError(f"{source}: line 1: CSV must include a 'text' column")

    width = len(headers)
    id_index = headers.index("id") if "id" in headers else None
    text_index = headers.index("text")

    data_rows = rows[1:]
    questions: list[Question] = []
    for offset, row in enumerate(data_rows):
        line_no = offset + 2  # 1-indexed, including header
        # Skip only genuine empty lines (Excel trailing \\n → len(row)==0).
        # Whitespace-bearing rows are kept and flagged — never silently dropped.
        if len(row) == 0:
            continue
        if len(row) != width:
            raise ValueError(
                f"{source}: line {line_no}: expected {width} field(s), got {len(row)}"
            )
        raw_id = row[id_index] if id_index is not None else None
        raw_text = row[text_index]
        # index = line_no - 1 so _auto_N matches the CSV line number (D1 / S1).
        questions.append(_question_from_fields(raw_id, raw_text, line_no - 1))

    if not questions:
        raise ValueError(f"{source}: CSV contains no question rows")

    return questions


def parse_questionnaire(path: InputPath | Path | str) -> Questionnaire:
    """Parse CSV or YAML into Question records under the documented schema."""
    ip = _coerce_input_path(path)
    source = ip.display
    try:
        is_file = ip.real.is_file()
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        raise OSError(exc.errno, f"cannot access {source}: {detail}") from None
    if not is_file:
        raise FileNotFoundError(f"questionnaire not found: {source}")

    suffix = ip.real.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        questions = _parse_questionnaire_yaml(ip)
    elif suffix == ".csv":
        questions = _parse_questionnaire_csv(ip)
    else:
        raise ValueError(
            f"{source}: unsupported questionnaire format {suffix!r}; "
            "use .yaml/.yml or .csv"
        )

    seen_ids: set[str] = set()
    for index, question in enumerate(questions):
        if question.id in seen_ids:
            questions[index] = Question(
                id=question.id,
                text=question.text,
                issues=question.issues + ("duplicate question id",),
            )
        seen_ids.add(question.id)

    for question in questions:
        for issue in question.issues:
            print(
                f"warning: {source}: {question.display_id}: {issue}",
                file=sys.stderr,
            )

    return Questionnaire(questions=questions, path=ip)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Draft grounded questionnaire answers from the SOC 2 / ISO 27001 "
            "control corpus, or abstain with INSUFFICIENT_COVERAGE."
        )
    )
    parser.add_argument(
        "--corpus",
        type=input_path,
        default=DEFAULT_CORPUS,
        help=(
            "path to a trusted mappings.yaml pin "
            "(default: corpus/mappings.yaml; trusted-input-only)"
        ),
    )
    parser.add_argument(
        "--questionnaire",
        type=input_path,
        required=True,
        help="path to questionnaire (.yaml/.yml or .csv)",
    )
    parser.add_argument(
        "--out-dir",
        type=input_path,
        default=DEFAULT_OUT_DIR,
        help="directory for responses.md and responses.json (default: drafts/)",
    )
    return parser


def _configure_stdio() -> None:
    """One print-boundary seam: ASCII terminals escape; UTF-8 shows real glyphs.

    Preserves printable non-ASCII in the data model (_safe_display_text) while
    keeping LC_ALL=C / PYTHONIOENCODING=ascii from killing mid-loop prints.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="backslashreplace")
        except (OSError, ValueError, AttributeError):
            continue


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    args = build_parser().parse_args(argv)

    try:
        corpus = load_corpus(args.corpus)
        questionnaire = parse_questionnaire(args.questionnaire)

        print(f"corpus: {corpus.path.display}")
        print(f"corpus version: {corpus.version}")
        print(f"mapping rows: {len(corpus.mappings)}")
        print(f"questionnaire: {questionnaire.path.display}")
        print(f"questions: {len(questionnaire.questions)}")

        records: list[dict] = []
        answered = 0
        for question in questionnaire.questions:
            preview = (
                _safe_display_text(question.text) if question.text else "(blank)"
            )
            print(f"  {question.display_id}: {preview}")
            record = build_record(question, corpus)
            records.append(record)
            if record["status"] == "answered":
                answered += 1

        out_ip = args.out_dir
        try:
            out_ip.real.mkdir(parents=True, exist_ok=True)
            md_path = out_ip.real / "responses.md"
            json_path = out_ip.real / "responses.json"
            md_path.write_text(render_markdown(records, corpus), encoding="utf-8")
            json_path.write_text(render_json(records, corpus), encoding="utf-8")
        except OSError as exc:
            detail = exc.strerror or type(exc).__name__
            raise OSError(
                exc.errno, f"cannot write {out_ip.display}: {detail}"
            ) from None

        total = len(records)
        pct = _coverage_pct(answered, total)
        abstained = total - answered
        print(f"coverage: {answered}/{total} ({pct}%)")
        print(f"answered: {answered} | abstained: {abstained} | total: {total}")
        tier_order = ("Strong", "Partial", "Contextual")
        tier_counts = {tier: 0 for tier in tier_order}
        for record in records:
            if record["status"] != "answered":
                continue
            conf = record["confidence"]
            if conf in tier_counts:
                tier_counts[conf] += 1
        print(
            "tiers: "
            + " | ".join(f"{tier} {tier_counts[tier]}" for tier in tier_order)
        )
        for record in records:
            if record["status"] != "INSUFFICIENT_COVERAGE":
                continue
            qid = _safe_display_text(record["question_id"])
            reason = _safe_display_text(record["reason"])
            print(f"  abstain {qid}: {reason}")
        for name in ("responses.md", "responses.json"):
            shown = f"{out_ip.display.rstrip('/')}/{name}"
            print(f"wrote: {_safe_display_text(shown)}")

        return 0
    except RecursionError:
        # Deep customer YAML nests blow the parser — fault is the file, not the tool.
        print(
            "error: input nesting exceeds parser limits; "
            "simplify the questionnaire or corpus file",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, yaml.YAMLError, csv.Error) as exc:
        # Operator-fixable input / IO / encoding problems (incl. UnicodeEncodeError).
        print(f"error: {_format_cli_error(exc)}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — catch-all; distinct prefix
        # Tool defect — type name kept, exit 1, never a traceback.
        print(
            f"internal error: {_format_cli_error(exc, include_type=True)}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
