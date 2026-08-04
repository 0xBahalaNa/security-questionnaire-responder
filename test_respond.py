"""Strict-schema tests for corpus loader + questionnaire parser."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from hypothesis import given, settings, strategies as st

from respond import (
    REPO_ROOT,
    _UNSAFE_UNICODE_CATEGORIES,
    _format_cli_error,
    _safe_display_text,
    _validate_mapping_row,
    build_parser,
    check_questionnaire_schema,
    input_path,
    load_corpus,
    main,
    parse_questionnaire,
)

SAMPLE = REPO_ROOT / "samples" / "caiq_lite_excerpt.yaml"
CORPUS = REPO_ROOT / "corpus" / "mappings.yaml"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path




class CorpusLoaderTests(unittest.TestCase):
    def test_vendored_corpus_loads(self) -> None:
        corpus = load_corpus(CORPUS)
        self.assertEqual(corpus.version, "1.0")
        self.assertEqual(len(corpus.mappings), 9)

    def test_corpus_flag_loads_alternate_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alt.yaml"
            _write(
                path,
                "metadata:\n  version: '9.9'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: alternate pin\n",
            )
            corpus = load_corpus(path)
            self.assertEqual(corpus.version, "9.9")
            self.assertEqual(main(["--corpus", str(path), "--questionnaire", str(SAMPLE)]), 0)

    def test_rejects_merge_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "defaults: &d\n  confidence: Strong\n"
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - <<: *d\n"
                "    soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("merge keys", str(ctx.exception))

    def test_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    soc2_cc: CC6.2\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("duplicate key", str(ctx.exception))

    def test_empty_nist_equals_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    nist_800_53: []\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            self.assertEqual(load_corpus(path).mappings[0].nist_800_53, ())

    def test_rejects_non_string_soc2_cc(self) -> None:
        row = {
            "soc2_cc": ["CC6.1", "CC6.2"],
            "iso_27001_2022": ["A.5.15"],
            "confidence": "Strong",
            "rationale": "because",
        }
        with self.assertRaises(ValueError) as ctx:
            _validate_mapping_row(row, 0, source="corpus/mappings.yaml")
        self.assertIn("soc2_cc", str(ctx.exception))
        self.assertIn("corpus/mappings.yaml", str(ctx.exception))

    def test_rejects_invalid_confidence(self) -> None:
        row = {
            "soc2_cc": "CC6.1",
            "iso_27001_2022": ["A.5.15"],
            "confidence": "High",
            "rationale": "because",
        }
        with self.assertRaises(ValueError) as ctx:
            _validate_mapping_row(row, 0, source="corpus/mappings.yaml")
        self.assertIn("invalid confidence", str(ctx.exception))
        self.assertIn("corpus/mappings.yaml", str(ctx.exception))

    def test_padded_confidence_accepted(self) -> None:
        row = {
            "soc2_cc": "CC6.1",
            "iso_27001_2022": ["A.5.15"],
            "confidence": "Strong ",
            "rationale": "because",
        }
        _validate_mapping_row(row, 0, source="corpus/mappings.yaml")

    def test_padded_fields_normalized_on_load(self) -> None:
        """B9: assert normalization on the LOADED object, not only the validator."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: 'CC6.1 '\n"
                "    iso_27001_2022: [' A.5.15 ']\n"
                "    confidence: 'Strong '\n"
                "    rationale: ' because '\n",
            )
            row = load_corpus(path).mappings[0]
            self.assertEqual(row.confidence, "Strong")
            self.assertEqual(row.soc2_cc, "CC6.1")
            self.assertEqual(row.rationale, "because")
            self.assertEqual(row.iso_27001_2022, ("A.5.15",))

    def test_rejects_non_string_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: 1.10\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("metadata.version", str(ctx.exception))

    def test_rejects_row_count_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 99\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("row_count", str(ctx.exception))

    def test_rejects_row_count_bool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: true\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            msg = str(ctx.exception)
            self.assertIn("row_count", msg)
            self.assertIn("must be an int", msg)

    def test_rejects_row_count_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: '9'\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            msg = str(ctx.exception)
            self.assertIn("row_count", msg)
            self.assertIn("must be an int", msg)


class SchemaCheckTests(unittest.TestCase):
    def test_requires_questions_key(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_questionnaire_schema({"items": []}, source="t.yaml")
        self.assertIn("'questions'", str(ctx.exception))

    def test_rejects_items_alias(self) -> None:
        with self.assertRaises(ValueError):
            check_questionnaire_schema(
                {"items": [{"id": "Q1", "text": "x"}]},
                source="t.yaml",
            )

    def test_rejects_extra_root_key_alongside_questions(self) -> None:
        """B8: questions PLUS an extra root key must hit the unknown_root guard."""
        with self.assertRaises(ValueError) as ctx:
            check_questionnaire_schema(
                {
                    "questions": [{"id": "Q1", "text": "kept"}],
                    "items": [{"id": "Q2", "text": "dropped-if-ignored"}],
                },
                source="t.yaml",
            )
        self.assertIn("unexpected root key", str(ctx.exception))

    def test_rejects_mixed_item_shapes(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_questionnaire_schema(
                {"questions": ["bare", {"id": "Q1", "text": "x"}]},
                source="t.yaml",
            )
        self.assertIn("mixed", str(ctx.exception))

    def test_homogeneous_wrong_type_does_not_say_mixed(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_questionnaire_schema({"questions": [1, 2]}, source="t.yaml")
        msg = str(ctx.exception)
        self.assertNotIn("mixed", msg)
        self.assertIn("int", msg)

    def test_rejects_unknown_question_keys(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_questionnaire_schema(
                {"questions": [{"id": "Q1", "text": "x", "title": "nope"}]},
                source="t.yaml",
            )
        self.assertIn("unexpected key", str(ctx.exception))

    def test_rejects_non_string_id(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_questionnaire_schema(
                {"questions": [{"id": 10, "text": "x"}]},
                source="t.yaml",
            )
        self.assertIn("'id' must be a string", str(ctx.exception))


class QuestionnaireParserTests(unittest.TestCase):
    def test_sample_yaml(self) -> None:
        q = parse_questionnaire(SAMPLE)
        self.assertEqual(len(q.questions), 6)
        self.assertEqual(q.questions[5].issues, ("blank question text",))

    def test_rejects_questionnaire_merge_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "base: &b\n  text: from merge\n"
                "questions:\n  - <<: *b\n    id: Q1\n",
            )
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("merge keys", str(ctx.exception))

    def test_rejects_duplicate_question_text_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n"
                "  - id: Q1\n"
                "    text: FIRST real question\n"
                "    text: SECOND question\n",
            )
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("duplicate key", str(ctx.exception))

    def test_csv_happy_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,text\nCAIQ-01,Hello\nCAIQ-02,World\n")
            q = parse_questionnaire(path)
            self.assertEqual(
                [(item.id, item.text) for item in q.questions],
                [("CAIQ-01", "Hello"), ("CAIQ-02", "World")],
            )

    def test_csv_bom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            path.write_bytes(b"\xef\xbb\xbfid,text\nCAIQ-01,Hello\n")
            self.assertEqual(parse_questionnaire(path).questions[0].id, "CAIQ-01")

    def test_csv_rejects_unknown_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,question\nQ1,Hello\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("unexpected CSV header", str(ctx.exception))

    def test_csv_ragged_row_uses_line_number_including_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,text\nQ1,Hello\nQ2,World,extra\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("line 3:", str(ctx.exception))

    def test_csv_skips_blank_lines(self) -> None:
        """R3 regression: trailing Excel newline still parses."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,text\nQ1,Hello\n\n")
            q = parse_questionnaire(path)
            self.assertEqual(len(q.questions), 1)
            self.assertEqual(q.questions[0].text, "Hello")

    def test_csv_blank_text_row_kept_like_yaml(self) -> None:
        """B5: all-blank CSV data rows are kept+flagged, matching YAML."""
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "q.csv"
            yaml_path = Path(tmp) / "q.yaml"
            # Both cells empty — the R3 overshoot dropped this CSV row silently.
            _write(csv_path, "id,text\n,\nQ2,Real question\n")
            _write(
                yaml_path,
                "questions:\n"
                "  - text: ''\n"
                "  - id: Q2\n    text: Real question\n",
            )
            csv_q = parse_questionnaire(csv_path)
            yaml_q = parse_questionnaire(yaml_path)
            self.assertEqual(len(csv_q.questions), 2)
            self.assertEqual(len(yaml_q.questions), 2)
            self.assertEqual(csv_q.questions[0].text, yaml_q.questions[0].text)
            self.assertEqual(csv_q.questions[0].issues, yaml_q.questions[0].issues)
            self.assertIn("blank question text", csv_q.questions[0].issues)
            self.assertIn("substituted question id", csv_q.questions[0].issues)
            self.assertEqual(
                (csv_q.questions[1].id, csv_q.questions[1].text),
                (yaml_q.questions[1].id, yaml_q.questions[1].text),
            )

    def test_csv_trailing_whitespace_row_kept_and_flagged(self) -> None:
        """B2: whitespace-only final row is kept+flagged, not silently dropped."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "text\nQ one\n   \n")
            q = parse_questionnaire(path)
            self.assertEqual(len(q.questions), 2)
            self.assertEqual(q.questions[0].text, "Q one")
            self.assertIn("blank question text", q.questions[1].issues)
            self.assertEqual(q.questions[1].id, "_auto_3")

    def test_csv_whitespace_row_width_mismatch_not_dropped(self) -> None:
        """B2: trailing-newline variance must not silently accept a ragged row."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,text\nA,Q one\n   \n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("expected 2 field(s), got 1", str(ctx.exception))

    def test_csv_auto_id_uses_line_number(self) -> None:
        """D1: substituted ids key off CSV line number (incl. header), not list length."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "text\nHello\n\nWorld\n")
            q = parse_questionnaire(path)
            self.assertEqual([item.id for item in q.questions], ["_auto_2", "_auto_4"])

    def test_auto_id_semantics_differ_by_format(self) -> None:
        """S1: YAML list-position vs CSV line-number — pinned deliberate divergence."""
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "q.yaml"
            csv_path = Path(tmp) / "q.csv"
            _write(yaml_path, "questions:\n  - text: Hello\n  - text: World\n")
            _write(csv_path, "text\nHello\nWorld\n")
            yaml_ids = [item.id for item in parse_questionnaire(yaml_path).questions]
            csv_ids = [item.id for item in parse_questionnaire(csv_path).questions]
            self.assertEqual(yaml_ids, ["_auto_1", "_auto_2"])
            self.assertEqual(csv_ids, ["_auto_2", "_auto_3"])

    def test_csv_blank_header_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,,text\nQ1,x,Hello\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("blank header", str(ctx.exception))

    def test_csv_duplicate_header_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "text,text\nHello,World\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("duplicate CSV header", str(ctx.exception))

    def test_substituted_id_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "text\nHello\n")
            q = parse_questionnaire(path)
            # D1: _auto_N uses CSV line number (line 2 is the first data row).
            self.assertEqual(q.questions[0].id, "_auto_2")
            self.assertIn("substituted question id", q.questions[0].issues)

    def test_duplicate_ids_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - id: Q1\n    text: a\n  - id: Q1\n    text: b\n",
            )
            q = parse_questionnaire(path)
            self.assertIn("duplicate question id", q.questions[1].issues)

    def test_empty_questionnaire_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(path, "questions: []\n")
            self.assertEqual(main(["--questionnaire", str(path)]), 1)

    def test_input_path_repo_relative(self) -> None:
        shown = input_path(str(SAMPLE)).display
        self.assertEqual(shown, "samples/caiq_lite_excerpt.yaml")
        self.assertNotIn("/home/", shown)

    def test_input_path_out_of_repo_is_basename(self) -> None:
        """AC1 companion: out-of-repo file → basename only."""
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "Documents" / "Job" / "ExampleCo" / "caiq.csv"
            outside.parent.mkdir(parents=True)
            outside.touch()
            shown = input_path(str(outside)).display
            self.assertEqual(shown, "caiq.csv")
            self.assertNotIn("ExampleCo", shown)
            self.assertNotIn("Job", shown)
            self.assertNotIn(Path(tmp).name, shown)

    def test_input_path_directory_does_not_print_own_name(self) -> None:
        """Out-of-repo directory → <directory>, including via main()."""
        with tempfile.TemporaryDirectory() as tmp:
            company = Path(tmp) / "AcmeCorp"
            company.mkdir()
            shown = input_path(str(company)).display
            self.assertEqual(shown, "<directory>")
            self.assertNotIn("AcmeCorp", shown)
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(company)])
            finally:
                sys.stderr = old_err
            self.assertEqual(code, 1)
            self.assertIn("<directory>", err.getvalue())
            self.assertNotIn("AcmeCorp", err.getvalue())

    def test_safe_display_text_escapes_ansi(self) -> None:
        raw = "\x1b[2J\x1b[1;1Hcleared"
        shown = _safe_display_text(raw)
        self.assertNotIn("\x1b", shown)
        self.assertIn("cleared", shown)

    def test_safe_display_text_preserves_non_ascii(self) -> None:
        """B4: printable non-ASCII must survive; only controls are escaped."""
        french = "Est-ce que vous chiffrez les données ?"
        self.assertEqual(_safe_display_text(french), french)
        self.assertEqual(_safe_display_text("テスト"), "テスト")
        self.assertNotIn("\x1b", _safe_display_text("\x1b[31mx"))

    def test_question_id_display_sanitized_identity_verbatim(self) -> None:
        """B6: raw ESC stays in Question.id; display_id / stdout never emit it."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            path.write_bytes(b"id,text\n\x1b[2J\x1b[1;1HFAKE-ADMIN,Hello\n")
            parsed = parse_questionnaire(path)
            self.assertTrue(parsed.questions[0].id.startswith("\x1b"))
            self.assertNotIn("\x1b", parsed.questions[0].display_id)
            out = io.StringIO()
            err = io.StringIO()
            old_out, old_err = sys.stdout, sys.stderr
            try:
                sys.stdout, sys.stderr = out, err
                code = main(["--questionnaire", str(path)])
            finally:
                sys.stdout, sys.stderr = old_out, old_err
            self.assertEqual(code, 0)
            combined = out.getvalue() + err.getvalue()
            self.assertNotIn("\x1b", combined)
            self.assertIn("FAKE-ADMIN", combined)

    def test_question_id_soft_hyphen_stored_verbatim(self) -> None:
        """B6: U+00AD must remain in stored id so audit joins match the source row."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            soft = "CAIQ\u00ad-01"
            _write(path, f'questions:\n  - id: "{soft}"\n    text: Hello\n')
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[0].id, soft)
            self.assertIn("\\xad", q.questions[0].display_id)
            self.assertNotIn("\u00ad", q.questions[0].display_id)

    def test_main_success_stdout_has_no_home_path(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = out, err
            code = main(["--questionnaire", str(SAMPLE)])
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        self.assertEqual(code, 0)
        self.assertNotIn("/home/", out.getvalue())
        self.assertNotIn("/home/", err.getvalue())

    def test_main_malformed_yaml_error_scrubs_path_components(self) -> None:
        """B7: assert on path COMPONENTS under a fake company dir — not '/home/'."""
        with tempfile.TemporaryDirectory() as tmp:
            company_dir = Path(tmp) / "Documents" / "Job" / "AcmeCorp"
            company_dir.mkdir(parents=True)
            path = company_dir / "bad.yaml"
            _write(path, "questions:\n  - [ unterminated\n")
            out = io.StringIO()
            err = io.StringIO()
            old_out, old_err = sys.stdout, sys.stderr
            try:
                sys.stdout, sys.stderr = out, err
                code = main(["--questionnaire", str(path)])
            finally:
                sys.stdout, sys.stderr = old_out, old_err
            self.assertEqual(code, 1)
            combined = out.getvalue() + err.getvalue()
            self.assertIn("error:", combined)
            self.assertNotIn("internal error:", combined)
            self.assertNotIn("AcmeCorp", combined)
            self.assertNotIn("Job", combined)
            self.assertNotIn("Documents", combined)
            self.assertNotIn(Path(tmp).name, combined)
            self.assertNotIn("Traceback", combined)
            self.assertIn("bad.yaml", combined)

    def test_format_cli_error_preserves_non_path_slashes(self) -> None:
        """Slash-bearing non-path tokens stay intact (no post-hoc path regex)."""
        msg = _format_cli_error(
            ValueError(
                "invalid confidence 'Strong/Partial'; "
                "unexpected headers ['text/question']"
            ),
        )
        self.assertIn("Strong/Partial", msg)
        self.assertIn("text/question", msg)

    def test_format_cli_error_escapes_unsafe_unicode(self) -> None:
        """No Cc/Cf/Cs/Co/Cn char reaches the formatted error text."""
        raw = "bad id \x1b[31mFAKE\x1b[0m and soft\u00adhyphen and bidi \u202e"
        msg = _format_cli_error(ValueError(raw))
        for ch in msg:
            self.assertNotIn(
                unicodedata.category(ch),
                _UNSAFE_UNICODE_CATEGORIES,
                msg=f"unsafe {ch!r} survived in {msg!r}",
            )
        self.assertIn("FAKE", msg)
        self.assertIn("\\x1b", msg)
        self.assertIn("\\xad", msg)

    def test_m1_missing_file_under_company_dir_no_leak(self) -> None:
        """AC1: missing file under AcmeCorp prints neither AcmeCorp nor abs path."""
        with tempfile.TemporaryDirectory() as tmp:
            company = Path(tmp) / "AcmeCorp"
            company.mkdir()
            missing = company / "missing.yaml"
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(missing)])
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("error:", text)
            self.assertIn("missing.yaml", text)
            self.assertNotIn("AcmeCorp", text)
            self.assertNotIn(str(Path(tmp).resolve()), text)
            self.assertNotIn("/home/", text)
            self.assertNotIn("Traceback", text)

    def test_m1_unreadable_backslash_path_no_abs(self) -> None:
        """AC2: mode-000 file whose path contains a backslash — no absolute path."""
        with tempfile.TemporaryDirectory() as tmp:
            weird_dir = Path(tmp) / "dir\\name"
            weird_dir.mkdir(parents=True)
            path = weird_dir / "secret.yaml"
            _write(path, "questions:\n  - text: hi\n")
            os.chmod(path, 0o000)
            try:
                err = io.StringIO()
                old_err = sys.stderr
                try:
                    sys.stderr = err
                    code = main(["--questionnaire", str(path)])
                finally:
                    sys.stderr = old_err
                text = err.getvalue()
                self.assertEqual(code, 1)
                self.assertIn("error:", text)
                self.assertNotIn(str(path.resolve()), text)
                self.assertNotIn(str(Path(tmp).resolve()), text)
                self.assertNotIn("Traceback", text)
            finally:
                os.chmod(path, 0o644)

    def test_m1_non_utf8_path_component_no_abs(self) -> None:
        """AC3: non-UTF-8 path bytes — display is basename; no abs path on stderr."""
        with tempfile.TemporaryDirectory() as tmp:
            raw_name = b"caf\xe9.yaml"
            path = Path(tmp) / os.fsdecode(raw_name)
            _write(path, "questions:\n  - [ unterminated\n")
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", os.fsdecode(os.fsencode(path))])
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("error:", text)
            self.assertNotIn(str(Path(tmp).resolve()), text)
            self.assertNotIn("Traceback", text)

    def test_m1_empty_and_dot_questionnaire_no_token_corruption(self) -> None:
        """AC4: '' and '.' → <path>; message does not glue tokens together."""
        for raw in ("", "."):
            with self.subTest(raw=raw):
                err = io.StringIO()
                old_err = sys.stderr
                try:
                    sys.stderr = err
                    code = main(["--questionnaire", raw])
                finally:
                    sys.stderr = old_err
                text = err.getvalue()
                self.assertEqual(code, 1)
                self.assertIn("error:", text)
                self.assertIn("<path>", text)
                self.assertNotIn("badcorpus", text)
                self.assertNotIn("corpus<directory>", text)
                self.assertNotIn("Traceback", text)

    def test_m1_deleted_cwd_relative_questionnaire_no_traceback(self) -> None:
        """AC5: cwd deleted + relative questionnaire → exit 1, no traceback."""
        with tempfile.TemporaryDirectory() as outer:
            work = Path(outer) / "work"
            work.mkdir()
            _write(work / "q.yaml", "questions:\n  - text: hi\n")
            script = f"""
import os, sys
sys.path.insert(0, {str(REPO_ROOT)!r})
os.chdir({str(work)!r})
os.unlink("q.yaml")
os.rmdir({str(work)!r})
from respond import main
raise SystemExit(main(["--questionnaire", "q.yaml"]))
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=str(outer),
                capture_output=True,
                text=True,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.assertEqual(result.returncode, 1, msg=combined)
            self.assertIn("error:", combined)
            self.assertNotIn("Traceback", combined)
            self.assertNotIn(str(REPO_ROOT), combined)

    def test_m1_scrub_helpers_deleted(self) -> None:
        """AC6: post-hoc path scrubbers are gone."""
        source = (REPO_ROOT / "respond.py").read_text(encoding="utf-8")
        self.assertNotIn("_scrub_known_paths", source)
        self.assertNotIn("_path_text_forms", source)
        self.assertNotIn("_display_path", source)

    def test_e2_non_utf8_questionnaire_names_the_file(self) -> None:
        """E-2: a decode failure names the file, not just a byte offset."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "AcmeCorp_questions.yaml"
            path.write_bytes(b"questions:\n  - text: caf\xff\xfe\n")
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(path)])
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("AcmeCorp_questions.yaml", text)
            self.assertIn("not valid utf-8", text)
            self.assertNotIn(str(Path(tmp).resolve()), text)
            self.assertNotIn("Traceback", text)

    def test_e2_csv_error_names_file_and_line(self) -> None:
        """E-2: csv.Error mid-iteration names the file and the line number."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.csv"
            _write(path, 'id,text\nQ1,"' + "A" * 200000 + '"\n')
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(path)])
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("big.csv", text)
            self.assertIn("line ", text)
            self.assertNotIn(str(Path(tmp).resolve()), text)
            self.assertNotIn("Traceback", text)

    def test_e2_corpus_row_error_names_the_source(self) -> None:
        """E-2: corpus row errors name the pin, not just the row index."""
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "altpin.yaml"
            _write(
                bad,
                'metadata:\n  version: "1"\n  row_count: 1\n'
                "mappings:\n  - soc2_cc: CC6.1\n",
            )
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(
                    ["--corpus", str(bad), "--questionnaire", str(SAMPLE)]
                )
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("altpin.yaml", text)
            self.assertIn("mapping row 0", text)
            self.assertNotIn(str(Path(tmp).resolve()), text)
            self.assertNotIn("Traceback", text)

    def test_main_relative_path_scrubs_company_parent(self) -> None:
        """B3 live: cwd + relative company/file must not leak the company folder."""
        with tempfile.TemporaryDirectory() as tmp:
            company_dir = Path(tmp) / "AcmeCorp"
            company_dir.mkdir()
            path = company_dir / "bad.yaml"
            _write(path, "questions:\n  - [ unterminated\n")
            rel = Path("AcmeCorp") / "bad.yaml"
            out = io.StringIO()
            err = io.StringIO()
            old_out, old_err, old_cwd = sys.stdout, sys.stderr, Path.cwd()
            try:
                os.chdir(tmp)
                sys.stdout, sys.stderr = out, err
                code = main(["--questionnaire", str(rel)])
            finally:
                sys.stdout, sys.stderr = old_out, old_err
                os.chdir(old_cwd)
            combined = out.getvalue() + err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("error:", combined)
            self.assertNotIn("AcmeCorp", combined)
            self.assertIn("bad.yaml", combined)
            self.assertNotIn("Traceback", combined)

    def test_missing_relative_corpus_path_prints_intact(self) -> None:
        """B1 DONE: relative in-repo-shaped path is not slash-stripped."""
        rel_corpus = Path("corpus") / "nope.yaml"
        err = io.StringIO()
        old_err, old_cwd = sys.stderr, Path.cwd()
        try:
            os.chdir(REPO_ROOT)
            sys.stderr = err
            code = main(
                [
                    "--corpus",
                    str(rel_corpus),
                    "--questionnaire",
                    str(SAMPLE.relative_to(REPO_ROOT)),
                ]
            )
        finally:
            sys.stderr = old_err
            os.chdir(old_cwd)
        self.assertEqual(code, 1)
        text = err.getvalue()
        self.assertIn("corpus/nope.yaml", text)
        self.assertNotIn("corpusnope.yaml", text)

    def test_main_mixed_key_types_exit_clean(self) -> None:
        """Mixed non-string keys; assert schema message, not just exit 1."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.yaml"
            # int key + str key (not 1/True — those collide in a set because True == 1).
            # Plain sorted() would TypeError; _stable_sort_keys yields unexpected-key.
            _write(
                path,
                "questions:\n  - 1: junk\n    x: also\n    text: hello\n",
            )
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(path)])
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("error:", text)
            self.assertNotIn("internal error:", text)
            self.assertIn("unexpected key", text)
            self.assertNotIn("Traceback", text)

    def test_help_has_no_absolute_home_path(self) -> None:
        """B10: --help must not render DEFAULT_CORPUS as an absolute home path."""
        help_text = build_parser().format_help()
        self.assertNotIn(str(Path.home()), help_text)
        self.assertNotIn(str(REPO_ROOT), help_text)
        self.assertIn("corpus/mappings.yaml", help_text)

    def test_main_ascii_stdout_no_traceback_or_abs_path(self) -> None:
        """R-2 / B1: documented happy path must succeed under LC_ALL=C / ascii stdout."""
        env = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONIOENCODING": "ascii",
            "PYTHONPATH": str(REPO_ROOT),
        }
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "respond.py"),
                "--questionnaire",
                str(SAMPLE),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=combined)
        self.assertNotIn("Traceback", combined)
        self.assertNotIn(str(REPO_ROOT), combined)
        self.assertNotIn(str(Path.home()), combined)
        self.assertIn("mapping rows:", result.stdout)

    def test_main_ascii_stdout_prints_all_questions_with_non_ascii(self) -> None:
        """C-3/R-2: accented text must not swallow later ASCII questions on ascii stdout."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fr.yaml"
            _write(
                path,
                "questions:\n"
                "  - id: Q1\n"
                "    text: \"Est-ce que vous chiffrez les donn\u00e9es ?\"\n"
                "  - id: Q2\n"
                "    text: Pure ASCII follows accented text\n",
            )
            env = {
                **os.environ,
                "LC_ALL": "C",
                "LANG": "C",
                "PYTHONIOENCODING": "ascii",
                "PYTHONPATH": str(REPO_ROOT),
            }
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    "--questionnaire",
                    str(path),
                ],
                cwd=str(REPO_ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, msg=combined)
            self.assertIn("Q1:", result.stdout)
            self.assertIn("Q2:", result.stdout)
            self.assertIn("Pure ASCII follows accented text", result.stdout)
            self.assertNotIn("Traceback", combined)

    def test_main_deep_nesting_reports_input_error(self) -> None:
        """B7: RecursionError from deep YAML is error:, not internal error:."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep.yaml"
            # Deeply nested sequence — PyYAML recurses on construct.
            path.write_text("questions:\n  - " + ("[" * 3000) + ("]" * 3000) + "\n")
            err = io.StringIO()
            old_err = sys.stderr
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(path)])
            finally:
                sys.stderr = old_err
            text = err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("error:", text)
            self.assertNotIn("internal error:", text)
            self.assertIn("nesting", text)
            self.assertNotIn("Traceback", text)

    def test_internal_error_includes_exception_type(self) -> None:
        """B8: catch-all must keep the exception type name."""
        err = io.StringIO()
        old_err = sys.stderr
        with mock.patch(
            "respond.load_corpus",
            side_effect=AttributeError(
                "'NoneType' object has no attribute 'strip'"
            ),
        ):
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(SAMPLE)])
            finally:
                sys.stderr = old_err
        text = err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("internal error: AttributeError:", text)
        self.assertNotIn("Traceback", text)


# ---------------------------------------------------------------------------
# Property-based: never silently mangle; never accept-then-corrupt.
# ---------------------------------------------------------------------------

# Stick to plain ASCII so YAML dump/load cannot normalize exotic whitespace
# (e.g. NEL U+0085 → space) and falsely look like mangling in the tool.
_id_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    min_size=1,
    max_size=12,
)
_text_st = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S"),
        whitelist_characters=" ",
        codec="ascii",
    ),
    min_size=1,
    max_size=40,
).filter(lambda s: s.strip() != "")


class PropertyTests(unittest.TestCase):
    @given(st.lists(st.tuples(_id_st, _text_st), min_size=1, max_size=8, unique_by=lambda t: t[0]))
    @settings(max_examples=40, deadline=None)
    def test_yaml_round_trip_preserves_id_and_text(self, pairs: list[tuple[str, str]]) -> None:
        import yaml as yaml_mod

        doc = {
            "questions": [{"id": qid, "text": text} for qid, text in pairs],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            path.write_text(
                yaml_mod.safe_dump(doc, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            parsed = parse_questionnaire(path)
            self.assertEqual(
                [(q.id, q.text) for q in parsed.questions],
                [(qid, text.strip()) for qid, text in pairs],
            )

    @given(st.lists(st.tuples(_id_st, _text_st), min_size=1, max_size=8, unique_by=lambda t: t[0]))
    @settings(max_examples=40, deadline=None)
    def test_csv_round_trip_preserves_id_and_text(self, pairs: list[tuple[str, str]]) -> None:
        import csv as csv_mod

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv_mod.writer(handle)
                writer.writerow(["id", "text"])
                for qid, text in pairs:
                    writer.writerow([qid, text])
            parsed = parse_questionnaire(path)
            self.assertEqual(
                [(q.id, q.text) for q in parsed.questions],
                [(qid, text.strip()) for qid, text in pairs],
            )

    @given(
        st.sampled_from(
            [
                {"items": [{"id": "Q1", "text": "x"}]},
                {"questions": [{"id": "Q1", "text": "x", "extra": 1}]},
                {"questions": ["a", {"text": "b"}]},
                {"questions": [{"text": ["not", "a", "string"]}]},
                {"questions": []},
                "not a mapping",
            ]
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_invalid_schema_never_returns_questions(self, data: object) -> None:
        with self.assertRaises(ValueError):
            check_questionnaire_schema(data, source="property.yaml")


if __name__ == "__main__":
    unittest.main()
