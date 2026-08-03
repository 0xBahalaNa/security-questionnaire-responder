"""Invariant-level tests for corpus loader + questionnaire parser (issue #1)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from respond import (
    _alias_value,
    _normalize_key,
    _normalize_question,
    _validate_mapping_row,
    build_parser,
    load_corpus,
    main,
    parse_questionnaire,
)

REPO = Path(__file__).resolve().parent
SAMPLE = REPO / "samples" / "caiq_lite_excerpt.yaml"
CORPUS = REPO / "corpus" / "mappings.yaml"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _minimal_corpus(
    *,
    version: object = "'1.0'",
    row_count: object = 1,
    nist_line: str = "    nist_800_53: [AC-3]\n",
    confidence: str = "Strong",
) -> str:
    return (
        "metadata:\n"
        f"  version: {version}\n"
        f"  row_count: {row_count}\n"
        "mappings:\n"
        "  - soc2_cc: CC6.1\n"
        f"{nist_line}"
        "    iso_27001_2022: [A.5.15]\n"
        f"    confidence: {confidence}\n"
        "    rationale: x\n"
    )


class Inv1NoUncheckedStrCoercion(unittest.TestCase):
    """INV-1: never str()-coerce unvalidated values into id/text/version."""

    def test_rejects_list_question_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - id: Q1\n    text: [part a, part b]\n",
            )
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("text must be a string", str(ctx.exception))

    def test_rejects_mapping_question_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - id: {a: 1}\n    text: hello\n",
            )
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("id must be a string", str(ctx.exception))

    def test_rejects_unquoted_yaml_id_types(self) -> None:
        # PyYAML 1.1 would turn 010 -> 8, NO -> False without quotes.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(path, "questions:\n  - id: 010\n    text: hello\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("id must be a string", str(ctx.exception))

    def test_rejects_non_string_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(path, _minimal_corpus(version="1.10"))
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("metadata.version", str(ctx.exception))


class Inv2UsableAliasValue(unittest.TestCase):
    """INV-2: first usable alias wins; blank/null falls through."""

    def test_alias_skips_blank_text(self) -> None:
        value = _alias_value(
            {"text": "", "question": "Do you enforce MFA?"},
            ("text", "question", "question_text"),
        )
        self.assertEqual(value, "Do you enforce MFA?")

    def test_csv_blank_text_falls_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,text,question\nQ1,,Do you enforce MFA?\n")
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[0].text, "Do you enforce MFA?")
            self.assertNotIn("blank question text", q.questions[0].issues)

    def test_yaml_null_text_falls_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - id: Q1\n    text:\n    question: Real text\n",
            )
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[0].text, "Real text")


class Inv3HeaderNormalization(unittest.TestCase):
    """INV-3: normalize non-alphanumerics; collide = error."""

    def test_normalize_question_id_header(self) -> None:
        self.assertEqual(_normalize_key("Question ID"), "question_id")
        self.assertEqual(_normalize_key("question-id"), "question_id")
        self.assertEqual(_normalize_key("QUESTION ID"), "question_id")

    def test_csv_question_id_header_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "Question ID,Question\nCAIQ-AIS-01,Hello\n")
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[0].id, "CAIQ-AIS-01")
            self.assertEqual(q.questions[0].text, "Hello")

    def test_csv_normalized_header_collision_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,ID,text\nQ1,Q9,hello\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("duplicate CSV headers", str(ctx.exception))


class Inv4SubstitutionsFlagged(unittest.TestCase):
    """INV-4: every derived/substituted value gets an issue flag."""

    def test_auto_id_is_flagged(self) -> None:
        q = _normalize_question(None, "no id supplied", 0)
        self.assertEqual(q.id, "_auto_1")
        self.assertIn("substituted question id", q.issues)

    def test_blank_csv_id_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            _write(path, "id,text\n,Hello\n")
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[0].id, "_auto_1")
            self.assertIn("substituted question id", q.questions[0].issues)


class Inv5OptionalEmptyEqualsAbsent(unittest.TestCase):
    """INV-5: optional nist_800_53 absent and [] behave the same."""

    def test_empty_nist_list_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(path, _minimal_corpus(nist_line="    nist_800_53: []\n"))
            corpus = load_corpus(path)
            self.assertEqual(corpus.mappings[0].nist_800_53, ())

    def test_absent_nist_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(path, _minimal_corpus(nist_line=""))
            corpus = load_corpus(path)
            self.assertEqual(corpus.mappings[0].nist_800_53, ())


class Inv6NormalizeBeforeMembership(unittest.TestCase):
    """INV-6: strip before confidence membership check."""

    def test_padded_confidence_accepted(self) -> None:
        row = {
            "soc2_cc": "CC6.1",
            "iso_27001_2022": ["A.5.15"],
            "confidence": "Strong ",
            "rationale": "because",
        }
        _validate_mapping_row(row, 0)  # must not raise

    def test_padded_confidence_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(path, _minimal_corpus(confidence='"Strong "'))
            corpus = load_corpus(path)
            self.assertEqual(corpus.mappings[0].confidence, "Strong")


class Inv7CsvYamlParity(unittest.TestCase):
    """INV-7: CSV and YAML enforce the same guards and yield the same records."""

    def test_missing_text_field_errors_on_both(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "q.yaml"
            csv_path = Path(tmp) / "q.csv"
            _write(yaml_path, "questions:\n  - id: Q1\n    title: Not a text alias\n")
            _write(csv_path, "id,title\nQ1,Not a text alias\n")
            with self.assertRaises(ValueError) as yctx:
                parse_questionnaire(yaml_path)
            with self.assertRaises(ValueError) as cctx:
                parse_questionnaire(csv_path)
            self.assertIn("text/question", str(yctx.exception))
            self.assertIn("text/question", str(cctx.exception))

    def test_byte_equivalent_content_same_questions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = Path(tmp) / "q.yaml"
            csv_path = Path(tmp) / "q.csv"
            _write(
                yaml_path,
                "questions:\n"
                "  - id: CAIQ-AIS-01\n    text: Hello\n"
                "  - question_id: CAIQ-AIS-02\n    question: World\n",
            )
            _write(
                csv_path,
                "id,text\nCAIQ-AIS-01,Hello\nCAIQ-AIS-02,World\n",
            )
            # Second CSV row uses id/text; YAML second uses aliases — normalize
            # to the same resolved Question fields via a shared shape.
            yq = parse_questionnaire(yaml_path)
            cq = parse_questionnaire(csv_path)
            self.assertEqual(
                [(q.id, q.text, q.issues) for q in yq.questions],
                [(q.id, q.text, q.issues) for q in cq.questions],
            )

    def test_capitalized_yaml_keys_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - ID: Q1\n    Text: Capitalized keys work\n",
            )
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[0].id, "Q1")
            self.assertEqual(q.questions[0].text, "Capitalized keys work")


class Inv9NoDuplicateKeys(unittest.TestCase):
    """INV-9: a repeated mapping key is an error, never silent last-one-wins."""

    def test_duplicate_soc2_cc_in_row_errors(self) -> None:
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
            self.assertIn("duplicate key 'soc2_cc'", str(ctx.exception))

    def test_duplicate_confidence_in_row_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    confidence: Contextual\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("duplicate key 'confidence'", str(ctx.exception))

    def test_duplicate_metadata_version_errors(self) -> None:
        # Guard must cover metadata, not just mapping rows — version is stamped
        # into the JSON audit record.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  version: '9.9'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    confidence: Strong\n"
                "    rationale: x\n",
            )
            with self.assertRaises(ValueError) as ctx:
                load_corpus(path)
            self.assertIn("duplicate key 'version'", str(ctx.exception))

    def test_duplicate_question_text_errors(self) -> None:
        # Parity: the questionnaire path shares the strict loader. _normalize_
        # mapping_keys cannot see this — PyYAML collapses it before the dict.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - id: Q1\n    text: first\n    text: second\n",
            )
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("duplicate key 'text'", str(ctx.exception))

    def test_duplicate_key_reports_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(path, "questions:\n  - id: Q1\n    id: Q2\n    text: hi\n")
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("line 3", str(ctx.exception))

    def test_both_questions_and_items_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - {id: Q1, text: from-questions}\n"
                "items:\n  - {id: Q9, text: from-items}\n",
            )
            with self.assertRaises(ValueError) as ctx:
                parse_questionnaire(path)
            self.assertIn("both 'questions' and 'items'", str(ctx.exception))

    def test_shipped_inputs_still_load_under_strict_loader(self) -> None:
        # Regression: the guard must not reject the vendored corpus or sample.
        self.assertEqual(len(load_corpus(CORPUS).mappings), 9)
        self.assertEqual(len(parse_questionnaire(SAMPLE).questions), 6)


class RegressionAndSmoke(unittest.TestCase):
    def test_vendored_corpus_loads(self) -> None:
        corpus = load_corpus(CORPUS)
        self.assertEqual(corpus.version, "1.0")
        self.assertEqual(len(corpus.mappings), 9)

    def test_sample_yaml(self) -> None:
        q = parse_questionnaire(SAMPLE)
        self.assertEqual(len(q.questions), 6)
        self.assertEqual(q.questions[5].id, "Q6")
        self.assertEqual(q.questions[5].issues, ("blank question text",))

    def test_csv_bom_preserves_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.csv"
            path.write_bytes(
                b"\xef\xbb\xbfid,text\nCAIQ-AIS-01,Hello\nCAIQ-AIS-02,World\n"
            )
            q = parse_questionnaire(path)
            self.assertEqual(
                [item.id for item in q.questions],
                ["CAIQ-AIS-01", "CAIQ-AIS-02"],
            )

    def test_duplicate_ids_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(
                path,
                "questions:\n  - id: Q1\n    text: a\n  - id: Q1\n    text: b\n",
            )
            q = parse_questionnaire(path)
            self.assertEqual(q.questions[1].issues, ("duplicate question id",))

    def test_empty_questionnaire_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.yaml"
            _write(path, "questions: []\n")
            self.assertEqual(main(["--questionnaire", str(path)]), 1)

    def test_help_has_no_absolute_home_path(self) -> None:
        help_text = build_parser().format_help()
        self.assertNotIn("/home/", help_text)
        self.assertIn("corpus/mappings.yaml", help_text)

    def test_rejects_non_string_soc2_cc(self) -> None:
        row = {
            "soc2_cc": ["CC6.1", "CC6.2"],
            "iso_27001_2022": ["A.5.15"],
            "confidence": "Strong",
            "rationale": "because",
        }
        with self.assertRaises(ValueError) as ctx:
            _validate_mapping_row(row, 0)
        self.assertIn("soc2_cc", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
