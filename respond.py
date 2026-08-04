#!/usr/bin/env python3
"""Security questionnaire responder — input layer (corpus + questionnaire).

Two loaders, two trust models:
  - Corpus: vendored, trusted, maximum validation (citation source).
  - Questionnaire: customer-supplied, strict documented schema or reject.

Retrieval, drafting, and dual output land in later issues.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
import unicodedata
from collections.abc import Hashable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent

VALID_CONFIDENCE = ("Strong", "Partial", "Contextual")

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
            "Load the SOC 2 / ISO 27001 control corpus and parse a questionnaire "
            "(CSV or YAML) under a strict documented schema."
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

        flagged = sum(1 for q in questionnaire.questions if q.issues)
        print(f"corpus: {corpus.path.display}")
        print(f"corpus version: {corpus.version}")
        print(f"mapping rows: {len(corpus.mappings)}")
        print(f"questionnaire: {questionnaire.path.display}")
        print(f"questions: {len(questionnaire.questions)} ({flagged} with issues)")

        for row in corpus.mappings:
            iso = ", ".join(row.iso_27001_2022)
            print(f"  [{row.confidence}] {row.soc2_cc} -> {iso}")

        for question in questionnaire.questions:
            preview = (
                _safe_display_text(question.text) if question.text else "(blank)"
            )
            flag = f"  issues={list(question.issues)}" if question.issues else ""
            print(f"  {question.display_id}: {preview}{flag}")

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
