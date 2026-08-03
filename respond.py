#!/usr/bin/env python3
"""Security questionnaire responder — input layer (corpus + questionnaire).

Loads a vendored SOC 2 / ISO 27001 mapping corpus and parses a customer
questionnaire (CSV or YAML) into a normalized question list. Retrieval,
drafting, and dual output land in later issues; this file is the boundary
that fails loudly on malformed inputs.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections.abc import Hashable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Default: vendored pin committed in-repo (offline-first / clone-and-run).
DEFAULT_CORPUS = Path(__file__).resolve().parent / "corpus" / "mappings.yaml"

VALID_CONFIDENCE = ("Strong", "Partial", "Contextual")

# Shared by CSV and YAML parsers so alias support cannot drift apart.
QUESTION_ID_ALIASES = ("id", "question_id", "qid")
QUESTION_TEXT_ALIASES = ("text", "question", "question_text")

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of last-one-wins.

    PyYAML resolves a repeated key silently, so `soc2_cc:` twice in a corpus row
    would load as the second value and cite the wrong criterion. Duplicates are
    only visible on the parse node, before it collapses into a dict.
    """

    def construct_mapping(self, node, deep: bool = False):
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, Hashable):
                # SafeLoader raises its own unhashable-key error below.
                continue
            if key in seen:
                raise ValueError(
                    f"duplicate key {key!r} at line {key_node.start_mark.line + 1}"
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _load_yaml_strict(handle: Any) -> Any:
    """Single YAML entry point — corpus and questionnaire share one parser."""
    return yaml.load(handle, Loader=_StrictLoader)


def _normalize_key(name: str) -> str:
    """Lowercase and collapse non-alphanumerics so 'Question ID' == 'question_id'."""
    return _NON_ALNUM.sub("_", name.strip().lower()).strip("_")


def _is_usable(value: Any) -> bool:
    """True when an alias value is worth selecting (not null/blank)."""
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def _alias_value(mapping: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    """Return the first usable alias value, or None if none are usable."""
    for key in aliases:
        if key in mapping and _is_usable(mapping[key]):
            return mapping[key]
    return None


def _normalize_mapping_keys(mapping: dict[Any, Any], *, context: str) -> dict[str, Any]:
    """Rewrite keys with _normalize_key; collide on the same norm → error."""
    normalized: dict[str, Any] = {}
    for raw_key, value in mapping.items():
        if not isinstance(raw_key, str):
            raise ValueError(
                f"{context}: mapping keys must be strings, "
                f"got {type(raw_key).__name__}"
            )
        key = _normalize_key(raw_key)
        if not key:
            raise ValueError(f"{context}: mapping key {raw_key!r} normalizes to empty")
        if key in normalized:
            raise ValueError(
                f"{context}: duplicate keys after normalization: {raw_key!r} "
                f"collides with an earlier header/field"
            )
        normalized[key] = value
    return normalized


def _require_text_alias_present(keys: set[str], *, context: str) -> None:
    """CSV and YAML both require at least one text/question field name."""
    if not any(alias in keys for alias in QUESTION_TEXT_ALIASES):
        raise ValueError(
            f"{context}: must include a text/question field; got {sorted(keys)}"
        )


def _validate_string_list(
    value: Any,
    index: int,
    field_name: str,
    *,
    allow_empty: bool = False,
) -> None:
    """Require a list of non-blank strings (ISO / NIST ref lists)."""
    if not isinstance(value, list):
        raise ValueError(
            f"mapping row {index}: {field_name} must be a list of strings, "
            f"got {type(value).__name__}"
        )
    if len(value) == 0:
        if allow_empty:
            return
        raise ValueError(f"mapping row {index}: blank field {field_name!r}")
    for element_index, element in enumerate(value):
        if not isinstance(element, str) or not element.strip():
            raise ValueError(
                f"mapping row {index}: {field_name}[{element_index}] must be a "
                f"non-blank string, got {element!r}"
            )


def _validate_mapping_row(row: dict, index: int) -> None:
    """Raise ValueError if a mapping row is missing required grounding fields."""

    required = ("soc2_cc", "iso_27001_2022", "confidence", "rationale")

    for field_name in required:
        if field_name not in row:
            raise ValueError(f"mapping row {index}: missing field {field_name!r}")

        value = row[field_name]

        if value is None:
            raise ValueError(f"mapping row {index}: blank field {field_name!r}")

        if isinstance(value, str) and not value.strip():
            raise ValueError(f"mapping row {index}: blank field {field_name!r}")

        if isinstance(value, list) and len(value) == 0:
            raise ValueError(f"mapping row {index}: blank field {field_name!r}")

    # Citation keys must be real strings — never invent a label via str(list).
    for field_name in ("soc2_cc", "rationale"):
        if not isinstance(row[field_name], str):
            raise ValueError(
                f"mapping row {index}: {field_name} must be a string, "
                f"got {type(row[field_name]).__name__}"
            )

    if not isinstance(row["confidence"], str):
        raise ValueError(
            f"mapping row {index}: confidence must be a string, "
            f"got {type(row['confidence']).__name__}"
        )

    # Strip before membership so whitespace-padded tiers match siblings.
    confidence = row["confidence"].strip()
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(
            f"mapping row {index}: invalid confidence {row['confidence']!r}"
        )

    _validate_string_list(row["iso_27001_2022"], index, "iso_27001_2022")


@dataclass(frozen=True)
class MappingRow:
    """One grounded mapping from the corpus — citation source for later stages."""

    soc2_cc: str
    iso_27001_2022: tuple[str, ...]
    confidence: str
    rationale: str
    nist_800_53: tuple[str, ...] = ()


@dataclass(frozen=True)
class Corpus:
    """In-memory control corpus. version is stamped into the JSON audit record (#4)."""

    version: str
    mappings: tuple[MappingRow, ...]
    path: Path


@dataclass(frozen=True)
class Question:
    """Normalized questionnaire item — format-agnostic record for retrieval."""

    id: str
    text: str
    issues: tuple[str, ...] = ()


@dataclass
class Questionnaire:
    """Parsed questionnaire plus any row-level problems reported (not dropped)."""

    questions: list[Question] = field(default_factory=list)
    path: Path | None = None


def load_corpus(path: Path | None = None) -> Corpus:
    """Read and validate the mapping corpus. Fail loudly — never load partially.

    TL;DR: open the YAML, require every mapping row to be groundable, return
    version + rows for downstream citation.

    The Three Questions:
      - Have: a Path to mappings.yaml
      - Need: Corpus(version, mappings) with validated rows
      - Stop: after every row validates, or on first ValueError / parse error
    """
    corpus_path = path if path is not None else DEFAULT_CORPUS
    if not corpus_path.is_file():
        raise FileNotFoundError(f"corpus not found: {corpus_path}")

    with corpus_path.open(encoding="utf-8") as handle:
        raw = _load_yaml_strict(handle)

    if not isinstance(raw, dict):
        raise ValueError(f"corpus root must be a mapping, got {type(raw).__name__}")

    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("corpus missing metadata mapping")

    version = metadata.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError(
            "corpus metadata.version must be a non-blank string "
            f"(quote it in YAML), got {version!r}"
        )
    version = version.strip()

    if "row_count" not in metadata:
        raise ValueError("corpus metadata.row_count is required")
    row_count = metadata["row_count"]
    # bool is a subclass of int — reject it explicitly so True/False cannot pass.
    if isinstance(row_count, bool) or not isinstance(row_count, int):
        raise ValueError(
            f"corpus metadata.row_count must be an int, got {row_count!r} "
            f"({type(row_count).__name__})"
        )

    rows_raw = raw.get("mappings")
    if not isinstance(rows_raw, list) or len(rows_raw) == 0:
        raise ValueError("corpus mappings must be a non-empty list")

    mappings: list[MappingRow] = []
    for index, row in enumerate(rows_raw):
        if not isinstance(row, dict):
            raise ValueError(
                f"mapping row {index}: expected a mapping, got {type(row).__name__}"
            )
        _validate_mapping_row(row, index)

        # Optional bridge column: absent and [] both mean "no NIST mapping".
        if "nist_800_53" not in row or row["nist_800_53"] is None:
            nist: list[Any] = []
        else:
            nist = row["nist_800_53"]
            _validate_string_list(nist, index, "nist_800_53", allow_empty=True)

        mappings.append(
            MappingRow(
                soc2_cc=row["soc2_cc"].strip(),
                iso_27001_2022=tuple(item.strip() for item in row["iso_27001_2022"]),
                confidence=row["confidence"].strip(),
                rationale=row["rationale"].strip(),
                nist_800_53=tuple(item.strip() for item in nist),
            )
        )

    if row_count != len(mappings):
        raise ValueError(
            f"corpus metadata.row_count is {row_count} but loaded "
            f"{len(mappings)} mapping rows"
        )

    return Corpus(version=version, mappings=tuple(mappings), path=corpus_path)


def _normalize_question(raw_id: Any, raw_text: Any, index: int) -> Question:
    """Build a Question; blank text and substituted IDs become issues, not drops."""
    issues: list[str] = []

    if raw_id is None or (isinstance(raw_id, str) and not raw_id.strip()):
        # Private prefix so fallbacks cannot collide with customer ids like Q1.
        qid = f"_auto_{index + 1}"
        issues.append("substituted question id")
    elif not isinstance(raw_id, str):
        raise ValueError(
            f"question {index}: id must be a string (quote the value in YAML), "
            f"got {type(raw_id).__name__}"
        )
    else:
        qid = raw_id.strip()

    if raw_text is None or (isinstance(raw_text, str) and not raw_text.strip()):
        text = ""
        issues.append("blank question text")
    elif not isinstance(raw_text, str):
        raise ValueError(
            f"question {index}: text must be a string, "
            f"got {type(raw_text).__name__}"
        )
    else:
        text = raw_text.strip()

    return Question(id=qid, text=text, issues=tuple(issues))


def _question_from_mapping(item: dict[Any, Any], index: int, *, context: str) -> Question:
    """Shared CSV/YAML path: normalize keys, resolve aliases, build Question."""
    normalized = _normalize_mapping_keys(item, context=f"{context}: question {index}")
    return _normalize_question(
        _alias_value(normalized, QUESTION_ID_ALIASES),
        _alias_value(normalized, QUESTION_TEXT_ALIASES),
        index,
    )


def _parse_questionnaire_yaml(path: Path) -> list[Question]:
    with path.open(encoding="utf-8") as handle:
        raw = _load_yaml_strict(handle)

    if raw is None:
        return []

    if isinstance(raw, dict):
        # Both keys present is ambiguous — refuse rather than drop half the file.
        present = [key for key in ("questions", "items") if key in raw]
        if not present:
            raise ValueError(
                f"{path}: YAML root mapping must contain 'questions' (or 'items')"
            )
        if len(present) > 1:
            raise ValueError(
                f"{path}: both 'questions' and 'items' are present; use exactly one"
            )
        items = raw[present[0]]
        if items is None:
            raise ValueError(
                f"{path}: {present[0]!r} is present but null; expected a list"
            )
    elif isinstance(raw, list):
        items = raw
    else:
        raise ValueError(f"{path}: YAML root must be a list or mapping")

    if not isinstance(items, list):
        raise ValueError(f"{path}: questions must be a list")

    dict_items = [item for item in items if isinstance(item, dict)]
    if dict_items:
        # Same guard as CSV: at least one text/question field name must exist.
        key_union: set[str] = set()
        for item in dict_items:
            for raw_key in item:
                if isinstance(raw_key, str):
                    key_union.add(_normalize_key(raw_key))
        _require_text_alias_present(key_union, context=str(path))

    questions: list[Question] = []
    for index, item in enumerate(items):
        if isinstance(item, str):
            questions.append(_normalize_question(None, item, index))
            continue
        if not isinstance(item, dict):
            raise ValueError(
                f"{path}: question {index} must be a string or mapping, "
                f"got {type(item).__name__}"
            )
        questions.append(_question_from_mapping(item, index, context=str(path)))
    return questions


def _parse_questionnaire_csv(path: Path) -> list[Question]:
    # utf-8-sig strips a leading BOM so Excel-exported headers still match.
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: CSV has no header row")

        header_map: dict[str, str] = {}
        for name in reader.fieldnames:
            if not name:
                continue
            norm = _normalize_key(name)
            if not norm:
                raise ValueError(f"{path}: CSV header {name!r} normalizes to empty")
            if norm in header_map:
                raise ValueError(
                    f"{path}: duplicate CSV headers after normalization: "
                    f"{name!r} collides with {header_map[norm]!r}"
                )
            header_map[norm] = name

        _require_text_alias_present(set(header_map), context=str(path))

        questions: list[Question] = []
        for index, row in enumerate(reader):
            normalized = {
                _normalize_key(key): value
                for key, value in row.items()
                if key
            }
            questions.append(
                _normalize_question(
                    _alias_value(normalized, QUESTION_ID_ALIASES),
                    _alias_value(normalized, QUESTION_TEXT_ALIASES),
                    index,
                )
            )
        return questions


def parse_questionnaire(path: Path) -> Questionnaire:
    """Parse CSV or YAML into a common question record (id, text).

    TL;DR: one shape for both formats so retrieval never cares how the
    customer sent the questionnaire.

    Blank question text and substituted IDs are kept with issue flags — never
    silently dropped. An empty questionnaire raises — coverage rate over zero
    questions is a misleading success.
    """
    if not path.is_file():
        raise FileNotFoundError(f"questionnaire not found: {path}")

    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        questions = _parse_questionnaire_yaml(path)
    elif suffix == ".csv":
        questions = _parse_questionnaire_csv(path)
    else:
        raise ValueError(
            f"unsupported questionnaire format {suffix!r}; use .yaml/.yml or .csv"
        )

    # Duplicate IDs — report, don't drop.
    seen_ids: set[str] = set()
    for index, question in enumerate(questions):
        if question.id in seen_ids:
            question = Question(
                id=question.id,
                text=question.text,
                issues=question.issues + ("duplicate question id",),
            )
            questions[index] = question
        seen_ids.add(question.id)

    if len(questions) == 0:
        raise ValueError(f"{path}: questionnaire contains no questions")

    for question in questions:
        for issue in question.issues:
            print(
                f"warning: {path}: {question.id}: {issue}",
                file=sys.stderr,
            )

    return Questionnaire(questions=questions, path=path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Load the SOC 2 / ISO 27001 control corpus and parse a questionnaire "
            "(CSV or YAML) into normalized question records."
        )
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
        # Repo-relative in help so a local absolute path never ships publicly.
        help="path to mappings.yaml (default: corpus/mappings.yaml)",
    )
    parser.add_argument(
        "--questionnaire",
        type=Path,
        required=True,
        help="path to questionnaire (.yaml/.yml or .csv)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        corpus = load_corpus(args.corpus)
        questionnaire = parse_questionnaire(args.questionnaire)
    except (OSError, ValueError, yaml.YAMLError, csv.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    flagged = sum(1 for q in questionnaire.questions if q.issues)
    print(f"corpus: {corpus.path}")
    print(f"corpus version: {corpus.version}")
    print(f"mapping rows: {len(corpus.mappings)}")
    print(f"questionnaire: {questionnaire.path}")
    print(f"questions: {len(questionnaire.questions)} ({flagged} with issues)")

    # Preview — useful while later stages are not yet wired.
    for row in corpus.mappings:
        iso = ", ".join(row.iso_27001_2022)
        print(f"  [{row.confidence}] {row.soc2_cc} → {iso}")

    for question in questionnaire.questions:
        preview = question.text if question.text else "(blank)"
        flag = f"  issues={list(question.issues)}" if question.issues else ""
        print(f"  {question.id}: {preview}{flag}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
