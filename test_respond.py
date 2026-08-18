"""Strict-schema tests for corpus loader + questionnaire parser."""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from hypothesis import given, settings, strategies as st

import itertools

from respond import (
    FRAMEWORK_TOKENS,
    MIN_SECURITY_TOKENS,
    MappingRow,
    REPO_ROOT,
    SECURITY_VOCABULARY,
    STOPWORDS,
    TERM_EQUIVALENCE,
    Question,
    _UNSAFE_UNICODE_CATEGORIES,
    _format_cli_error,
    _safe_display_text,
    _validate_mapping_row,
    build_parser,
    check_questionnaire_schema,
    cited_row_ids,
    corpus_vocabulary,
    input_path,
    load_corpus,
    main,
    normalize_token,
    parse_questionnaire,
    retrieve,
    score_question_against_row,
    suggest_owner,
    tokenize,
)
import respond as respond_mod

SAMPLE = REPO_ROOT / "samples" / "caiq_lite_excerpt.yaml"
CORPUS = REPO_ROOT / "corpus" / "mappings.yaml"

# AC 24 — pin the expected set in the suite, not by reading the live frozenset.
# Includes Decision 19 crosswalk verbs + B-A corpus metaphor/narration tokens.
EXPECTED_FRAMEWORK_TOKENS = frozenset(
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

# B-A / R-4 — corpus metaphor & narration tokens that must never score.
# Hand-reviewed against vendored rationales; plurals listed explicitly (no TE wideners).
METAPHOR_NARRATION_TOKENS = frozenset(
    {
        "angle",
        "angles",
        "blend",
        "blends",
        "broad",
        "closer",
        "depth",
        "door",
        "foot",
        "get",
        "gets",
        "hop",
        "keep",
        "keeps",
        "loop",
        "loose",
        "pivot",
        "pure",
    }
)

# S1 / Decision 18 — STOPWORDS pin (domain fillers live here too).
EXPECTED_STOPWORDS = frozenset(
    {
        "a",
        "about",
        "above",
        "after",
        "again",
        "against",
        "all",
        "already",
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
        "even",
        "few",
        "for",
        "from",
        "full",
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
        "including",
        "into",
        "is",
        "it",
        "its",
        "itself",
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

# AC 5 / Decision 18 — hand-reviewed families. NOT derived from TERM_EQUIVALENCE.
EXPECTED_FAMILIES: frozenset[frozenset[str]] = frozenset(
    {
        frozenset({"access", "accessed", "accessing"}),
        frozenset({"account", "accounts"}),
        frozenset({"activities", "activity"}),
        frozenset({"address", "addressed", "addresses", "addressing"}),
        frozenset({"align", "aligns"}),
        frozenset({"analyze", "analyzed", "analyzes", "analyzing"}),
        frozenset({"annex", "annexes"}),
        frozenset({"anomalies", "anomaly"}),
        frozenset({"application", "applications"}),
        frozenset({"approve", "approved", "approves", "approving"}),
        frozenset({"audit", "audits"}),
        frozenset({"auditor", "auditors"}),
        frozenset({"authorization", "authorizations"}),
        frozenset({"authorize", "authorized", "authorizes", "authorizing"}),
        frozenset({"base", "based"}),
        frozenset({"baseline", "baselines"}),
        frozenset({"boundaries", "boundary"}),
        frozenset({"certification", "certifications"}),
        frozenset({"change", "changed", "changes", "changing"}),
        frozenset({"component", "components"}),
        frozenset({"configuration", "configurations"}),
        frozenset({"control", "controls"}),
        frozenset({"cover", "covers"}),
        frozenset({"credential", "credentials"}),
        frozenset({"criteria", "criterion"}),
        frozenset({"define", "defined", "defines", "defining"}),
        frozenset({"deviation", "deviations"}),
        frozenset({"device", "devices"}),
        frozenset({"disable", "disabled", "disables", "disabling"}),
        frozenset({"document", "documented", "documenting", "documents"}),
        frozenset({"duties", "duty"}),
        frozenset({"enforce", "enforced", "enforces", "enforcing"}),
        frozenset({"event", "events"}),
        frozenset({"finding", "findings"}),
        frozenset({"frame", "frames"}),
        frozenset({"framework", "frameworks"}),
        frozenset({"identity", "identities"}),
        frozenset({"implement", "implemented", "implementing", "implements"}),
        frozenset({"incident", "incidents"}),
        frozenset({"issue", "issued", "issues", "issuing"}),
        frozenset({"layer", "layers"}),
        frozenset({"log", "logged", "logging", "logs"}),
        frozenset({"maintain", "maintained", "maintaining", "maintains"}),
        frozenset({"map", "maps"}),
        frozenset({"measure", "measured", "measures", "measuring"}),
        frozenset({"mechanism", "mechanisms"}),
        frozenset({"modified", "modifies", "modify", "modifying"}),
        frozenset({"monitor", "monitored", "monitoring", "monitors"}),
        frozenset({"policy", "policies"}),
        frozenset({"privilege", "privileged", "privileges"}),
        frozenset({"procedure", "procedures"}),
        frozenset({"process", "processed", "processes"}),
        frozenset({"deprovision", "deprovisioned", "deprovisioning"}),
        frozenset({"provision", "provisioned", "provisioning"}),
        frozenset({"record", "recorded", "recording", "records"}),
        frozenset({"remove", "removed", "removes", "removing"}),
        frozenset(
            {"require", "required", "requirements", "requires", "requiring"}
        ),
        frozenset({"restriction", "restrictions"}),
        frozenset({"review", "reviewed", "reviewing", "reviews"}),
        frozenset({"revocation", "revoke", "revoked", "revokes"}),
        frozenset({"right", "rights"}),
        frozenset({"role", "roles"}),
        frozenset({"service", "services"}),
        frozenset({"setting", "settings"}),
        frozenset({"system", "systems"}),
        frozenset({"task", "tasks"}),
        frozenset({"threat", "threats"}),
        frozenset({"type", "types"}),
        frozenset({"user", "users"}),
    }
)

# AC 42 — pin expected SECURITY_VOCABULARY; never derive from production.
# Keep in sync with respond.SECURITY_VOCABULARY by hand (Decision 18 / R-8).
EXPECTED_SECURITY_VOCABULARY = frozenset(
    {
        "access",
        "account",
        "analyze",
        "anomaly",
        "approval",
        "approve",
        "authentication",
        "authenticator",
        "authorization",
        "authorize",
        "baseline",
        "boundary",
        "change",
        "component",
        "configuration",
        "credential",
        "deviation",
        "disable",
        "enforce",
        "enforcement",
        "event",
        "hardened",
        "identification",
        "identity",
        "implement",
        "incident",
        "least",
        "lifecycle",
        "log",
        "logical",
        "measure",
        "monitor",
        "policy",
        "privilege",
        "provision",
        "record",
        "registration",
        "removal",
        "remove",
        "restriction",
        "restrictive",
        "revocation",
        "risk",
        "role",
        "rotation",
        "scan",
        "secure",
        "security",
        "setting",
        "system",
        "threat",
        "user",
    }
)

# AC 40 — pinned fabrication probes. Docstring / comments record prior false grounds.
FABRICATION_PROBES: tuple[str, ...] = (
    "How do you define the subset selection for each component type?",  # was CC7.2 Strong 5
    "Is the agreement binding outside our organizational boundary?",  # was CC6.6 Strong 4
    "How do you measure the strength of a unique brand identity?",  # was CC6.6 Strong 4
    "Did the ticket state the deviation from the document?",  # was CC8.1 Contextual 4
    "What is the potential frequency of a marketing event?",  # was CC7.3 Strong 3
    "What is the baseline alignment for the new design?",  # was CC8.1 Partial 3
    "What information is necessary to change my task?",  # was CC6.3 Strong 4
    "What is the default on-call rotation policy?",  # was CC6.6 Partial 3
    "Who owns the information architecture and the intent of each layer?",  # was CC6.1 Strong 4
    "Is a change to the task necessary?",  # was CC6.3 Strong 3
)

# AC 41 / 45 — legitimate probes must ground to the expected criterion.
LEGITIMATE_PROBES: tuple[tuple[str, str], ...] = (
    (
        "Describe how you enforce logical access controls for production systems.",
        "CC6.1",
    ),
    (
        "How do you provision and authorize new user accounts before credentials are issued?",
        "CC6.2",
    ),
    (
        "How do you enforce least privilege for administrative access?",
        "CC6.3",
    ),
    (
        "What authentication controls do you require for users accessing the system?",
        "CC6.6",
    ),
    ("How do you monitor system components for anomalies?", "CC7.2"),
    ("How do you evaluate security events for potential incidents?", "CC7.3"),
    ("Do you maintain hardened baseline configurations?", "CC8.1"),
    (
        "How do you revoke credentials when an employee leaves the company?",
        "CC6.6",
    ),
    # Offboarding "deprovision*" must NOT appear here expecting CC6.2 — that
    # was the G-1 polarity bug (onboarding criterion answering offboarding).
    (
        "What are your password policies and rotation requirements?",
        "CC6.6",
    ),
    ("Who approves a change before implementing it?", "CC8.1"),
)

# AC 46 — hand-reviewed inflections that MUST normalize to each canonical.
# NOT derived from TERM_EQUIVALENCE. Deleting "policies" must turn this RED.
REQUIRED_INFLECTIONS: dict[str, frozenset[str]] = {
    "access": frozenset({"accessed", "accessing"}),
    "account": frozenset({"accounts"}),
    "activity": frozenset({"activities"}),
    "address": frozenset({"addresses", "addressed", "addressing"}),
    "analyze": frozenset({"analyzed", "analyzing", "analyzes"}),
    "anomaly": frozenset({"anomalies"}),
    "application": frozenset({"applications"}),
    "approve": frozenset({"approved", "approves", "approving"}),
    "authorization": frozenset({"authorizations"}),
    "authorize": frozenset({"authorized", "authorizes", "authorizing"}),
    "baseline": frozenset({"baselines"}),
    "boundary": frozenset({"boundaries"}),
    "change": frozenset({"changes", "changed", "changing"}),
    "component": frozenset({"components"}),
    "configuration": frozenset({"configurations"}),
    "credential": frozenset({"credentials"}),
    "define": frozenset({"defined", "defines", "defining"}),
    "deviation": frozenset({"deviations"}),
    "disable": frozenset({"disabled", "disables", "disabling"}),
    "document": frozenset({"documents", "documented", "documenting"}),
    "duty": frozenset({"duties"}),
    "enforce": frozenset({"enforces", "enforced", "enforcing"}),
    "event": frozenset({"events"}),
    "finding": frozenset({"findings"}),
    "identity": frozenset({"identities"}),
    "implement": frozenset({"implements", "implemented", "implementing"}),
    "incident": frozenset({"incidents"}),
    "issue": frozenset({"issued", "issues", "issuing"}),
    "layer": frozenset({"layers"}),
    "log": frozenset({"logged", "logging", "logs"}),
    "maintain": frozenset({"maintains", "maintaining", "maintained"}),
    "measure": frozenset({"measures", "measured", "measuring"}),
    "mechanism": frozenset({"mechanisms"}),
    "modify": frozenset({"modified", "modifies", "modifying"}),
    "monitor": frozenset({"monitors", "monitoring", "monitored"}),
    "policy": frozenset({"policies"}),
    "privilege": frozenset({"privileged", "privileges"}),
    "provision": frozenset({"provisioning", "provisioned"}),
    "record": frozenset({"records", "recorded", "recording"}),
    "remove": frozenset({"removed", "removes", "removing"}),
    "require": frozenset(
        {"requires", "required", "requiring", "requirements"}
    ),
    "restriction": frozenset({"restrictions"}),
    "review": frozenset({"reviews", "reviewed", "reviewing"}),
    "revocation": frozenset({"revoke", "revoked", "revokes"}),
    "right": frozenset({"rights"}),
    "role": frozenset({"roles"}),
    "setting": frozenset({"settings"}),
    "system": frozenset({"systems"}),
    "task": frozenset({"tasks"}),
    "threat": frozenset({"threats"}),
    "type": frozenset({"types"}),
    "user": frozenset({"users"}),
}

# AC 7 / Decision 18 — hand-reviewed against vendored corpus rationales (BOTH directions).
# Metaphor/narration tokens are filtered (B-A) and must NOT appear here.
# Equality assertion — added OR removed vocabulary fails the suite.
EXPECTED_CORPUS_VOCABULARY = frozenset(
    {
        "access",
        "account",
        "activity",
        "address",
        "adequacy",
        "adjusting",
        "alignment",
        "analytic",
        "analyze",
        "anomaly",
        "application",
        "approval",
        "approve",
        "architecture",
        "artifact",
        "assigned",
        "assignment",
        "authentication",
        "authenticator",
        "authorization",
        "authorize",
        "base",
        "baseline",
        "binding",
        "boundary",
        "change",
        "component",
        "config",
        "configuration",
        "create",
        "credential",
        "default",
        "define",
        "demonstrates",
        "depends",
        "design",
        "develops",
        "deviation",
        "disable",
        "document",
        "duty",
        "enforce",
        "enforcement",
        "establishes",
        "evaluates",
        "event",
        "evidence",
        "expects",
        "finding",
        "frequency",
        "governs",
        "hardened",
        "identification",
        "identifying",
        "identity",
        "implement",
        "incident",
        "information",
        "install",
        "intent",
        "investigative",
        "issuance",
        "issue",
        "layer",
        "least",
        "lifecycle",
        "log",
        "logical",
        "maintain",
        "manages",
        "measure",
        "mechanism",
        "minimization",
        "modification",
        "modify",
        "monitor",
        "necessary",
        "onboarding",
        "organizational",
        "outside",
        "policy",
        "posture",
        "potential",
        "privilege",
        "provision",
        "record",
        "registration",
        "removal",
        "remove",
        "reporting",
        "require",
        "restriction",
        "restrictive",
        "review",
        "revocation",
        "right",
        "risk",
        "role",
        "rotation",
        "satisfy",
        "scan",
        "scap",
        "secure",
        "security",
        "segregation",
        "selecting",
        "selection",
        "separately",
        "separates",
        "setting",
        "state",
        "stig",
        "strength",
        "subset",
        "supports",
        "system",
        "task",
        "technical",
        "test",
        "threat",
        "ticket",
        "type",
        "unique",
        "upgrade",
        "user",
    }
)

# AC 35 — counterpart families incl. corpus-side plurality/lifecycle (occurrence 10).
REQUIRED_COUNTERPART_FAMILIES: tuple[frozenset[str], ...] = (
    frozenset({"privilege", "privileged", "privileges"}),
    frozenset({"enforce", "enforces", "enforced", "enforcing"}),
    frozenset({"provision", "provisioning", "provisioned"}),
    frozenset({"authorize", "authorizes", "authorized", "authorizing"}),
    frozenset({"define", "defines", "defined", "defining"}),
    frozenset({"implement", "implements", "implemented"}),
    frozenset({"type", "types"}),
    frozenset({"task", "tasks"}),
    frozenset({"disable", "disabled", "disables"}),
    frozenset({"remove", "removed", "removes"}),
    frozenset({"modify", "modified", "modifies"}),
)

def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _write_large_questionnaire(
    path: Path, n: int = 3000, text: str = "x"
) -> Path:
    parts = ["questions:\n"]
    parts.extend(f"  - id: Q{i}\n    text: {text}\n" for i in range(n))
    return _write(path, "".join(parts))


def _sample_questions() -> dict[str, Question]:
    questionnaire = parse_questionnaire(SAMPLE)
    return {question.id: question for question in questionnaire.questions}


def _row_by_soc2(corpus, soc2_cc: str, *, nist: str | None = None):
    for row in corpus.mappings:
        if row.soc2_cc != soc2_cc:
            continue
        if nist is None or nist in row.nist_800_53:
            return row
    raise AssertionError(f"no corpus row for {soc2_cc!r} nist={nist!r}")


# AC 1a — verified revision-1 false grounds and off-corpus items.
NEGATIVE_CONTROL_QUESTIONS: tuple[tuple[str, str], ...] = (
    ("insurance", "Do you carry cyber insurance of at least 5 million?"),
    ("pci", "Describe your PCI DSS 3.2 requirement 8 password policy."),
    (
        "meta-1",
        "Do you support SOC 2 Type 2 and ISO 27001 Annex A 8 requirements?",
    ),
    ("meta-2", "Is your product SOC 2 compliant under section 5 and 15?"),
    ("meta-3", "Do you support SOC 2 Type 2 audits and ISO 9001?"),
    ("incidents", "Were there 2 or 3 incidents in the last 5 years?"),
    ("bcp", "Can employees be reached on call in an emergency?"),
    ("hr", "Do you perform background checks on new employees?"),
    (
        "pentest",
        "How often do you engage a third party for penetration testing?",
    ),
    ("residency", "What is your data residency commitment for EU customers?"),
)

KNOWN_LIMITATION_QUESTION = (
    "Do you have a documented policy that is reviewed on a defined frequency?"
)
KNOWN_LIMITATION_STRONG_QUESTION = (
    "How frequently do you review your information security policy?"
)


class RetrievalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = load_corpus(CORPUS)
        cls.questions = _sample_questions()

    def _sole_hit(self, result):
        self.assertFalse(result.is_empty)
        self.assertFalse(result.is_ambiguous)
        return result.hits[0]

    def test_retrieve_q1_hits_cc61_exact_matched_tokens(self) -> None:
        """AC 49: pins CC6.1 row identity and exact matched-token tuple."""
        hit = self._sole_hit(retrieve(self.questions["Q1"], self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC6.1")
        self.assertEqual(
            hit.matched_tokens, ("access", "enforce", "logical", "system")
        )

    def test_retrieve_q2_hits_cc62(self) -> None:
        hit = self._sole_hit(retrieve(self.questions["Q2"], self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC6.2")
        self.assertEqual(
            hit.matched_tokens,
            ("account", "credential", "issue", "provision", "user"),
        )
       
    def test_retrieve_q3_hits_cc63(self) -> None:
        hit = self._sole_hit(retrieve(self.questions["Q3"], self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC6.3")
        self.assertEqual(hit.matched_tokens, ("access", "least", "privilege"))

    def test_retrieve_q4_hits_cc66_ia2(self) -> None:
        hit = self._sole_hit(retrieve(self.questions["Q4"], self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC6.6")
        self.assertEqual(hit.row.nist_800_53, ("IA-2",))

    def test_retrieve_q5_outside_corpus_is_empty(self) -> None:
        result = retrieve(self.questions["Q5"], self.corpus)
        self.assertTrue(result.is_empty)
        self.assertEqual(result.hits, ())

    def test_retrieve_blank_question_is_empty(self) -> None:
        result = retrieve(self.questions["Q6"], self.corpus)
        self.assertTrue(result.is_empty)

    def test_retrieve_q2_matched_tokens_exact(self) -> None:
        """AC 34: exact tuple pin — cross-process determinism is via PYTHONHASHSEED runs."""
        hit = self._sole_hit(retrieve(self.questions["Q2"], self.corpus))
        self.assertEqual(
            hit.matched_tokens,
            ("account", "credential", "issue", "provision", "user"),
        )
       
    def test_negative_control_fixture_abstains(self) -> None:
        for case_id, text in NEGATIVE_CONTROL_QUESTIONS:
            with self.subTest(case=case_id):
                result = retrieve(Question(id=case_id, text=text), self.corpus)
                self.assertTrue(result.is_empty)

    def test_positive_control_fixture_still_grounds(self) -> None:
        expectations = (
            ("Q1", "CC6.1"),
            ("Q2", "CC6.2"),
            ("Q3", "CC6.3"),
            ("Q4", "CC6.6"),
        )
        for qid, soc2_cc in expectations:
            with self.subTest(question=qid):
                hit = self._sole_hit(retrieve(self.questions[qid], self.corpus))
                self.assertEqual(hit.row.soc2_cc, soc2_cc)

        audit = Question(
            id="AUDIT",
            text=(
                "How do you analyze security event records for potential incidents?"
            ),
        )
        hit = self._sole_hit(retrieve(audit, self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC7.3")

    def test_unicode_ligature_and_soft_hyphen_ground_like_ascii(self) -> None:
        """AC 12 carry-forward: NFKC + Cf-strip keep PDF/Word variants equivalent."""
        baseline_ascii = Question(
            id="cfg-ascii",
            text="Describe your configuration baseline under control.",
        )
        baseline_lig = Question(
            id="cfg-lig",
            text="Describe your conﬁguration baseline under control.",
        )
        ascii_hit = self._sole_hit(retrieve(baseline_ascii, self.corpus))
        lig_hit = self._sole_hit(retrieve(baseline_lig, self.corpus))
        self.assertEqual(lig_hit.row.soc2_cc, ascii_hit.row.soc2_cc)
        self.assertEqual(lig_hit.matched_tokens, ascii_hit.matched_tokens)

        soft_hyphen = Question(
            id="Q1-shy",
            text=(
                "Describe how you enforce logi\u00adcal access controls for "
                "production systems."
            ),
        )
        q1_hit = self._sole_hit(retrieve(self.questions["Q1"], self.corpus))
        shy_hit = self._sole_hit(retrieve(soft_hyphen, self.corpus))
        self.assertEqual(shy_hit.row.soc2_cc, q1_hit.row.soc2_cc)
        self.assertEqual(shy_hit.matched_tokens, q1_hit.matched_tokens)

    def test_policy_frequency_generic_phrasing_abstains(self) -> None:
        """Decision 14 shape under Decision 21: narration-only overlap cannot ground.

        Matched tokens were define/frequency/review — none are security vocabulary,
        so the former CC7.3/CC8.1 tie is empty rather than ambiguous.
        """
        result = retrieve(
            Question(id="POLICY", text=KNOWN_LIMITATION_QUESTION), self.corpus
        )
        self.assertTrue(result.is_empty)
        self.assertEqual(result.hits, ())

    def test_known_limitation_strong_tier_misground_is_pinned(self) -> None:
        """Lexical candidate can still reach Strong before M2r classification."""
        hit = self._sole_hit(
            retrieve(
                Question(
                    id="POLICY-STRONG", text=KNOWN_LIMITATION_STRONG_QUESTION
                ),
                self.corpus,
            )
        )
        self.assertEqual(hit.row.soc2_cc, "CC6.1")
        self.assertEqual(hit.row.confidence, "Strong")
        self.assertEqual(hit.score, 3)
        self.assertEqual(
            hit.matched_tokens, ("information", "policy", "security")
        )

    def test_retrieve_returns_partial_row_when_it_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cm1.yaml"
            _write(
                path,
                "questions:\n"
                "  - id: CM1\n"
                "    text: How do you maintain baseline configuration under "
                "configuration control?\n",
            )
            question = parse_questionnaire(path).questions[0]
            hit = self._sole_hit(retrieve(question, self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC8.1")
        self.assertEqual(hit.row.confidence, "Partial")
        self.assertEqual(hit.row.nist_800_53, ("CM-2",))

    def test_retrieve_returns_contextual_row_when_it_wins(self) -> None:
        """AC 20: Contextual row is reachable — never filtered by tier."""
        question = Question(
            id="CM6",
            text=(
                "How do you establish restrictive configuration settings and "
                "monitor changes to settings?"
            ),
        )
        hit = self._sole_hit(retrieve(question, self.corpus))
        self.assertEqual(hit.row.soc2_cc, "CC8.1")
        self.assertEqual(hit.row.confidence, "Contextual")
        self.assertEqual(hit.row.nist_800_53, ("CM-6",))

    def test_tokenize_drops_stopwords_and_short_tokens(self) -> None:
        self.assertEqual(
            tokenize("How do you enforce access?"),
            ("enforce", "access"),
        )
        self.assertNotIn("eu", tokenize("Describe EU region access"))
        self.assertIn("log", tokenize("What event types do you select to log?"))
        # "new" is STOPWORDS (B2) — contentless filler must not survive tokenize.
        self.assertNotIn("new", tokenize("authorize new users before credentials"))
        self.assertEqual(
            tokenize("authorize new users before credentials"),
            ("authorize", "user", "credential"),
        )

    def test_tokenize_strips_control_ids_from_prose(self) -> None:
        tokens = tokenize("CC6.1 maps to logical access controls")
        # "maps"→"map" is Decision-19 framework boilerplate; controls→control filtered.
        self.assertEqual(tokens, ("logical", "access"))
        self.assertNotIn("cc6", tokens)
        self.assertNotIn("map", tokens)

    def test_zero_width_separator_splits_rather_than_fuses(self) -> None:
        self.assertEqual(
            tokenize("least\u200bprivilege"),
            ("least", "privilege"),
        )
        zw_q3 = Question(
            id="Q3-zw",
            text="How do you enforce least\u200bprivilege for privileged access?",
        )
        ascii_hit = self._sole_hit(retrieve(self.questions["Q3"], self.corpus))
        zw_hit = self._sole_hit(retrieve(zw_q3, self.corpus))
        self.assertEqual(zw_hit.row.soc2_cc, ascii_hit.row.soc2_cc)
        self.assertEqual(zw_hit.matched_tokens, ascii_hit.matched_tokens)
        self.assertEqual(tokenize("logi\u00adcal"), tokenize("logical"))

    def test_accent_fold_does_not_fabricate_real_words(self) -> None:
        self.assertEqual(tokenize("autenticación"), ("autenticacion",))
        self.assertNotIn("sum", tokenize("résumé"))
        self.assertEqual(tokenize("résumé"), ("resume",))

    def test_normalize_token_idempotent_and_unlisted(self) -> None:
        """AC 1–2: values are not keys; unlisted tokens are identity."""
        for key in TERM_EQUIVALENCE:
            once = normalize_token(key)
            self.assertEqual(normalize_token(once), once)
            self.assertNotIn(once, TERM_EQUIVALENCE)
        self.assertEqual(normalize_token("zzzunlisted"), "zzzunlisted")

    def test_normalize_conflates_ac3_and_ac4_families(self) -> None:
        """AC 3–4: broken stemmer families and prior AC-12 families."""
        families = (
            ("access", "accessed", "accessing"),
            ("setting", "settings"),
            ("issue", "issued"),
            ("measure", "measures"),
            ("process", "processed", "processes"),
            ("base", "based"),
            ("role", "roles"),
            ("device", "devices"),
            ("service", "services"),
            ("procedure", "procedures"),
            ("require", "requires", "required", "requiring"),
            ("review", "reviews", "reviewed", "reviewing"),
            ("account", "accounts"),
            ("analyze", "analyzed", "analyzing"),
        )
        for family in families:
            with self.subTest(family=family[0]):
                canonicals = {normalize_token(token) for token in family}
                self.assertEqual(len(canonicals), 1, canonicals)

    def test_no_wrong_conflation_across_expected_families(self) -> None:
        """AC 5: multi-member buckets must be in the hand-reviewed EXPECTED_FAMILIES literal.

        Surface includes table keys so an injected wrong conflation is visible;
        the expectation (EXPECTED_FAMILIES) is never derived from the table.
        """
        surface = set(EXPECTED_CORPUS_VOCABULARY)
        for family in EXPECTED_FAMILIES:
            surface.update(family)
        surface.update(TERM_EQUIVALENCE)
        buckets: dict[str, set[str]] = {}
        for token in surface:
            buckets.setdefault(normalize_token(token), set()).add(token)
        for canonical, members in buckets.items():
            if len(members) <= 1:
                continue
            self.assertIn(
                frozenset(members),
                EXPECTED_FAMILIES,
                (canonical, members),
            )

    def test_stem_and_confidence_rank_removed(self) -> None:
        """AC 6 / C-6: stemmer and confidence-rank ordering are gone."""
        self.assertFalse(hasattr(respond_mod, "stem"))
        self.assertFalse(hasattr(respond_mod, "_STEM_FAMILIES"))
        self.assertFalse(hasattr(respond_mod, "CONFIDENCE_RANK"))
        self.assertFalse(hasattr(respond_mod, "_UNKNOWN_CONFIDENCE_RANK"))
        self.assertFalse(hasattr(respond_mod, "_families_from_term_equivalence"))

    def test_corpus_vocabulary_matches_reviewed_literal(self) -> None:
        """AC 7: equality both ways — added OR removed vocabulary fails."""
        self.assertEqual(
            corpus_vocabulary(self.corpus), EXPECTED_CORPUS_VOCABULARY
        )
        # DONE: unreviewed upstream vocabulary turns the suite RED.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "drift.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    nist_800_53: [AC-3]\n"
                "    confidence: Strong\n"
                "    rationale: >-\n"
                "      offboarding is completed promptly\n",
            )
            drifted = corpus_vocabulary(load_corpus(path))
            self.assertIn("offboarding", drifted - EXPECTED_CORPUS_VOCABULARY)

    def test_filter_sets_are_canonical_forms(self) -> None:
        """AC 11: STOPWORDS / FRAMEWORK_TOKENS / SECURITY_VOCABULARY are not table keys."""
        for token in STOPWORDS | FRAMEWORK_TOKENS | SECURITY_VOCABULARY:
            self.assertNotIn(token, TERM_EQUIVALENCE)

    def test_boilerplate_plurals_filter_like_singulars(self) -> None:
        """AC 9–10: normalize-before-filter removes plural boilerplate."""
        self.assertEqual(
            tokenize(
                "Our audits, auditors, certifications, frameworks and annexes."
            ),
            (),
        )
        self.assertEqual(
            tokenize(
                "Our audit, auditor, certification, framework and annex."
            ),
            (),
        )
        # criteria / controls / crosswalk verbs — Decision 15 + 17 + 19.
        self.assertEqual(tokenize("criteria controls"), ())
        self.assertEqual(tokenize("maps aligns covers frames"), ())

    def test_measure_plural_singular_same_hits(self) -> None:
        """AC 14: tier must not flip on plural/singular phrasing."""
        plural = retrieve(
            Question(
                id="M-PL",
                text="What measures protect authentication credentials?",
            ),
            self.corpus,
        )
        singular = retrieve(
            Question(
                id="M-SG",
                text="What measure protects authentication credentials?",
            ),
            self.corpus,
        )
        self.assertEqual(plural.hits, singular.hits)
        self.assertTrue(plural.is_ambiguous)

    def test_score_tie_surfaces_all_rows_by_corpus_index(self) -> None:
        """AC 15–16: ties are ambiguous; Contextual before Strong by index."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tie.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 2\n"
                "mappings:\n"
                "  - soc2_cc: CC8.1\n"
                "    iso_27001_2022: [A.8.9]\n"
                "    nist_800_53: [CM-6]\n"
                "    confidence: Contextual\n"
                "    rationale: >-\n"
                "      shared marker access credential early contextual row\n"
                "  - soc2_cc: CC6.6\n"
                "    iso_27001_2022: [A.8.5]\n"
                "    nist_800_53: [IA-2]\n"
                "    confidence: Strong\n"
                "    rationale: >-\n"
                "      shared marker access credential later strong row\n",
            )
            corpus = load_corpus(path)
            result = retrieve(
                Question(
                    id="TIE",
                    text="Describe shared marker access credential for systems",
                ),
                corpus,
            )
        self.assertTrue(result.is_ambiguous)
        self.assertEqual(len(result.hits), 2)
        self.assertEqual(result.hits[0].row.confidence, "Contextual")
        self.assertEqual(result.hits[1].row.confidence, "Strong")
        self.assertEqual(
            [hit.row.nist_800_53 for hit in result.hits],
            [("CM-6",), ("IA-2",)],
        )

    def test_access_conflation_reaches_cc61_without_forcing_top_hit(self) -> None:
        """AC 17 (amended): accessed→access; CC6.1 matches; top hit may be CC7.3."""
        question = Question(
            id="ACC",
            text="Who has accessed customer records, and how is that logged?",
        )
        self.assertIn("access", tokenize(question.text))
        self.assertNotIn("acces", tokenize(question.text))
        row = _row_by_soc2(self.corpus, "CC6.1", nist="AC-3")
        score, matched, security_count = score_question_against_row(
            question, row
        )
        self.assertGreaterEqual(score, 1)
        self.assertIn("access", matched)
        self.assertIsInstance(security_count, int)
        self.assertEqual(row.nist_800_53, ("AC-3",))
        result = retrieve(question, self.corpus)
        hit = self._sole_hit(result)
        self.assertEqual(hit.row.soc2_cc, "CC7.3")
        self.assertEqual(hit.matched_tokens, ("log", "record"))

    def test_access_grant_and_data_accessed_same_hits(self) -> None:
        """AC 18 / AC 48: access / accessed phrasings agree; non-vacuous."""
        grant = retrieve(
            Question(
                id="G",
                text="Who has access to customer records that are logged?",
            ),
            self.corpus,
        )
        accessed = retrieve(
            Question(
                id="A",
                text="Who has accessed customer records that are logged?",
            ),
            self.corpus,
        )
        self.assertFalse(grant.is_empty)
        self.assertEqual(grant.hits, accessed.hits)

    def test_cited_row_ids_normalises_soc2_iso_nist(self) -> None:
        self.assertEqual(
            cited_row_ids("Provide your control description for SOC 2 CC6.1."),
            frozenset({"CC6.1"}),
        )
        self.assertEqual(
            cited_row_ids(
                "Describe your implementation of ISO 27001:2022 A.8.15."
            ),
            frozenset({"A.8.15"}),
        )
        self.assertEqual(
            cited_row_ids("See NIST AC-3 and IA-2."),
            frozenset({"AC-3", "IA-2"}),
        )

    def test_event_types_question_hits_cc72(self) -> None:
        hit = self._sole_hit(
            retrieve(
                Question(id="EVT", text="What event types does the system log?"),
                self.corpus,
            )
        )
        self.assertEqual(hit.row.soc2_cc, "CC7.2")
        self.assertEqual(hit.score, 4)

    def test_framework_tokens_match_expected_bound_set(self) -> None:
        self.assertEqual(FRAMEWORK_TOKENS, EXPECTED_FRAMEWORK_TOKENS)

    def test_stopwords_match_expected_bound_set(self) -> None:
        """S1 / Decision 18: STOPWORDS is pinned, including domain fillers."""
        self.assertEqual(STOPWORDS, EXPECTED_STOPWORDS)

    def test_each_framework_token_is_individually_bound(self) -> None:
        for fw in sorted(EXPECTED_FRAMEWORK_TOKENS):
            with self.subTest(token=fw):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / f"fw-{fw}.yaml"
                    _write(
                        path,
                        "metadata:\n  version: '1.0'\n  row_count: 1\n"
                        "mappings:\n"
                        "  - soc2_cc: CC6.1\n"
                        "    iso_27001_2022: [A.5.15]\n"
                        "    nist_800_53: [AC-3]\n"
                        "    confidence: Strong\n"
                        "    rationale: >-\n"
                        f"      widgetqqq {fw} markerzzz\n",
                    )
                    corpus = load_corpus(path)
                    question = Question(
                        id=f"FW-{fw}", text=f"Describe widgetqqq {fw}"
                    )
                    self.assertTrue(retrieve(question, corpus).is_empty)
                    self.assertNotIn(fw, tokenize(question.text))
                    self.assertNotIn(
                        normalize_token(fw), tokenize(question.text)
                    )

    def test_audit_logs_monitored_grounds_cc72(self) -> None:
        """B5 / Decision 13: tense/plural phrasing must not false-abstain."""
        hit = self._sole_hit(
            retrieve(
                Question(
                    id="LOGS",
                    text="Are audit logs monitored for anomalies?",
                ),
                self.corpus,
            )
        )
        self.assertEqual(hit.row.soc2_cc, "CC7.2")
        self.assertEqual(hit.matched_tokens, ("anomaly", "log", "monitor"))

    def test_b5_inflections_tokenize_to_canonical(self) -> None:
        """Decision 13 carry-forwards bind via tokenize(), not a table mirror."""
        cases = (
            ("logs", "log"),
            ("logging", "log"),
            ("monitored", "monitor"),
            ("documented", "document"),
            ("recorded", "record"),
            ("processes", "process"),
            ("authorized", "authorize"),
            ("privileges", "privilege"),
            ("enforced", "enforce"),
            ("enforcing", "enforce"),
            ("provisioned", "provision"),
            ("authorizing", "authorize"),
            ("defines", "define"),
            ("implemented", "implement"),
        )
        for inflection, canonical in cases:
            with self.subTest(inflection=inflection):
                self.assertEqual(tokenize(inflection), (canonical,))
                self.assertNotEqual(inflection, canonical)

    def test_shared_filter_path_no_side_parameter(self) -> None:
        """AC 32: tokenize has no side; framework tokens drop on both callers."""
        self.assertEqual(tokenize("audit control criterion"), ())
        self.assertNotIn("side", tokenize.__code__.co_varnames)

    def test_audit_trail_empty_is_known_limitation(self) -> None:
        """AC 33: Decision 17 documented cost — recall loss is pinned, not engineered around."""
        result = retrieve(
            Question(id="TRAIL", text="How do you review your audit trail?"),
            self.corpus,
        )
        self.assertTrue(result.is_empty)
        self.assertEqual(result.hits, ())

    def test_privilege_plural_singular_same_hits(self) -> None:
        """AC 35: privilege/privileges must not tier-flip or abstain asymmetrically."""
        singular = retrieve(
            Question(
                id="PRIV-SG",
                text="Describe restriction of administrator privilege.",
            ),
            self.corpus,
        )
        plural = retrieve(
            Question(
                id="PRIV-PL",
                text="Describe restriction of administrator privileges.",
            ),
            self.corpus,
        )
        self.assertEqual(singular.hits, plural.hits)
        self.assertFalse(singular.is_empty)
        self.assertEqual(singular.hits[0].row.soc2_cc, "CC6.3")

    def test_event_type_plural_singular_same_hits(self) -> None:
        """B1: corpus-side plurality must not flip CC7.2 to abstention."""
        plural = retrieve(
            Question(
                id="T-PL",
                text="What event types does the system log?",
            ),
            self.corpus,
        )
        singular = retrieve(
            Question(
                id="T-SG",
                text="What event type does the system log?",
            ),
            self.corpus,
        )
        self.assertEqual(plural.hits, singular.hits)
        self.assertFalse(singular.is_empty)
        self.assertEqual(singular.hits[0].row.soc2_cc, "CC7.2")

    def test_metaphor_narration_tokens_filtered_from_corpus_vocabulary(
        self,
    ) -> None:
        """B-A / R-4: every metaphor token is in FRAMEWORK_TOKENS and absent from vocab.

        Removing any one metaphor token from FRAMEWORK_TOKENS must turn this RED
        (AC 22) — the token re-enters corpus_vocabulary from the rationale text.
        """
        self.assertTrue(METAPHOR_NARRATION_TOKENS <= EXPECTED_FRAMEWORK_TOKENS)
        self.assertTrue(METAPHOR_NARRATION_TOKENS <= FRAMEWORK_TOKENS)
        leaked = corpus_vocabulary(self.corpus) & METAPHOR_NARRATION_TOKENS
        self.assertEqual(leaked, frozenset())
        for token in METAPHOR_NARRATION_TOKENS:
            with self.subTest(token=token):
                self.assertEqual(tokenize(token), ())

    def test_contentless_questions_cannot_ground(self) -> None:
        """B-A carry-forward: metaphor / STOPWORDS filler still abstain."""
        cases = (
            "Does your team keep a foot in the door on loose ends?",
            "Who manages and monitors the loop?",
            "Describe the management review, including new items.",
        )
        for text in cases:
            with self.subTest(text=text):
                result = retrieve(Question(id="EMPTY", text=text), self.corpus)
                self.assertTrue(result.is_empty, result.hits)

    @unittest.expectedFailure  # known limit — see README + DEMO-NOTES
    def test_fabrication_probes_all_abstain(self) -> None:
        """AC 40: every pinned fabrication probe returns empty.

        Known limit (issue #2 ship): lexical overlap with corpus rationale can
        clear retrieve() for ordinary non-security English; threshold/MARGIN
        cannot separate those from true positives without rejecting real
        access-control questions. Do not add another token blocklist to force
        this assert green — the README states the real scope.
        """
        still_ground: list[str] = []
        for text in FABRICATION_PROBES:
            result = retrieve(Question(id="FAB", text=text), self.corpus)
            if not result.is_empty:
                hit = result.hits[0]
                still_ground.append(
                    f"{hit.row.soc2_cc} {hit.row.confidence} s={hit.score} | {text}"
                )
        self.assertEqual(
            still_ground,
            [],
            "fabrication probes still grounding (draft vocab REVIEW queue):\n"
            + "\n".join(still_ground),
        )

    def test_legitimate_probes_ground_expected_criterion(self) -> None:
        """AC 41 / 45: legitimate probes ground to the expected soc2_cc."""
        for text, want in LEGITIMATE_PROBES:
            with self.subTest(text=text):
                result = retrieve(Question(id="LEG", text=text), self.corpus)
                got = {hit.row.soc2_cc for hit in result.hits}
                self.assertIn(
                    want,
                    got,
                    f"want {want} got {sorted(got) or ['EMPTY']} | {text}",
                )

    def test_security_vocabulary_matches_reviewed_literal(self) -> None:
        """AC 42: SECURITY_VOCABULARY is a hand-pinned literal (R-8)."""
        self.assertEqual(SECURITY_VOCABULARY, EXPECTED_SECURITY_VOCABULARY)
        self.assertEqual(MIN_SECURITY_TOKENS, 2)

    def test_each_security_vocabulary_entry_is_individually_bound(self) -> None:
        """AC 43: removing any SECURITY_VOCABULARY entry turns ≥1 assertion red.

        Synthetic pin: rationale/question share the entry plus one other
        security token. Full vocab grounds; removing the entry drops
        security_count below MIN_SECURITY_TOKENS.
        """
        tokens = sorted(EXPECTED_SECURITY_VOCABULARY)
        unbound: list[str] = []
        for token in tokens:
            other = next(t for t in tokens if t != token)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / f"sec-{token}.yaml"
                _write(
                    path,
                    "metadata:\n  version: '1.0'\n  row_count: 1\n"
                    "mappings:\n"
                    "  - soc2_cc: CC6.1\n"
                    "    iso_27001_2022: [A.5.15]\n"
                    "    nist_800_53: [AC-3]\n"
                    "    confidence: Strong\n"
                    "    rationale: >-\n"
                    f"      {other} {token} widgetmarker\n",
                )
                corpus = load_corpus(path)
                question = Question(
                    id=f"SEC-{token}",
                    text=f"Describe {other} and {token} for widgetmarker",
                )
                self.assertFalse(
                    retrieve(question, corpus).is_empty,
                    f"full vocab should ground on {token!r}",
                )
                reduced = SECURITY_VOCABULARY - {token}
                with mock.patch.object(
                    respond_mod, "SECURITY_VOCABULARY", reduced
                ):
                    if retrieve(question, corpus).is_empty:
                        continue
                    unbound.append(token)
        bound = len(EXPECTED_SECURITY_VOCABULARY) - len(unbound)
        self.assertEqual(
            unbound,
            [],
            f"bound={bound} unbound={len(unbound)}: {unbound}",
        )

    def test_narration_only_token_combinations_cannot_ground(self) -> None:
        """AC 44 / R-9: generated sweep over corpus narration vocabulary."""
        narration = corpus_vocabulary(self.corpus) - SECURITY_VOCABULARY
        # 2-token combinations drawn from narration — not a hand-picked list.
        grounded: list[str] = []
        for combo in itertools.combinations(sorted(narration), 2):
            text = "How do you handle " + ", ".join(combo) + "?"
            result = retrieve(Question(id="NARR", text=text), self.corpus)
            if not result.is_empty:
                grounded.append(text)
        self.assertEqual(grounded, [], grounded[:10])

    def test_monitor_scan_ambiguity_is_known_limitation(self) -> None:
        """AC 47: Decision 21 residual — monitor/scan still grounds (lexical limit).

        Lexical retrieval cannot resolve medical/ops senses. README limitations
        section lands at M3r.
        """
        result = retrieve(
            Question(
                id="AMB",
                text="How do you monitor posture and state during a scan?",
            ),
            self.corpus,
        )
        self.assertFalse(result.is_empty)

    def test_required_inflections_normalize_to_canonical(self) -> None:
        """AC 46: under-conflation guard — REQUIRED_INFLECTIONS → canonical."""
        for canonical, inflections in REQUIRED_INFLECTIONS.items():
            with self.subTest(canonical=canonical):
                self.assertIn(canonical, EXPECTED_CORPUS_VOCABULARY)
                for token in inflections:
                    self.assertEqual(normalize_token(token), canonical)

    def test_disabled_accounts_grounds_cc62(self) -> None:
        """B3: lifecycle tense — terminated/disabled accounts reach CC6.2."""
        hit = self._sole_hit(
            retrieve(
                Question(
                    id="TERM",
                    text="Are terminated employees' accounts disabled promptly?",
                ),
                self.corpus,
            )
        )
        self.assertEqual(hit.row.soc2_cc, "CC6.2")
        self.assertIn("disable", hit.matched_tokens)
        self.assertIn("account", hit.matched_tokens)

    def test_suggest_owner_monitoring_routes_to_secops(self) -> None:
        """OWNERS keys must be tokenize() canonicals — monitoring→monitor."""
        owner = suggest_owner(
            Question(
                id="MON",
                text=(
                    "Describe your monitoring of system components for anomalies."
                ),
            )
        )
        self.assertEqual(owner, "Security Operations")

    def test_owners_keys_are_tokenize_canonicals(self) -> None:
        """Every OWNERS key must be producible by tokenize() (S1 regression)."""
        for key in respond_mod.OWNERS:
            with self.subTest(key=key):
                self.assertIn(key, tokenize(key))

    def test_counterpart_families_all_conflate(self) -> None:
        """AC 35: every required counterpart family shares one canonical."""
        for family in REQUIRED_COUNTERPART_FAMILIES:
            with self.subTest(family=sorted(family)[0]):
                canonicals = {normalize_token(token) for token in family}
                self.assertEqual(len(canonicals), 1, canonicals)

    def test_crosswalk_verbs_cannot_ground(self) -> None:
        """AC 36: map/align/cover/frame are boilerplate, not content."""
        result = retrieve(
            Question(
                id="XW",
                text="How does your program map to and cover our requirements?",
            ),
            self.corpus,
        )
        self.assertTrue(result.is_empty)
        self.assertEqual(tokenize("maps aligns covers frames"), ())

    def test_mapping_row_derives_rationale_tokens_in_post_init(self) -> None:
        """AC 21: non-blank rationale cannot sit beside an empty token cache."""
        row = MappingRow(
            soc2_cc="CC6.1",
            iso_27001_2022=("A.5.15",),
            confidence="Strong",
            rationale="logical access enforcement mechanisms",
        )
        self.assertGreater(len(row.rationale_tokens), 0)
        self.assertIn("access", row.rationale_tokens)

    def test_mapping_row_empty_tokenize_loads_as_unmatchable(self) -> None:
        """B4(a): narration-only rationale loads with empty tokens — never aborts."""
        row = MappingRow(
            soc2_cc="CC6.1",
            iso_27001_2022=("A.5.15",),
            confidence="Strong",
            rationale=(
                "CC6.1 maps to ISO 27001 Annex A controls and NIST AC-3."
            ),
            source="pin.yaml",
            row_index=0,
        )
        self.assertEqual(row.rationale_tokens, ())

    def test_load_corpus_keeps_empty_tokenize_rows(self) -> None:
        """B4(a): YAML load must not abort on framework-narration-only rationale."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "narration.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    nist_800_53: [AC-3]\n"
                "    confidence: Strong\n"
                "    rationale: >-\n"
                "      CC6.1 maps to ISO 27001 Annex A controls and NIST AC-3.\n",
            )
            corpus = load_corpus(path)
            self.assertEqual(len(corpus.mappings), 1)
            self.assertEqual(corpus.mappings[0].rationale_tokens, ())
            self.assertTrue(
                retrieve(
                    Question(id="N", text="Describe logical access controls."),
                    corpus,
                ).is_empty
            )

    def test_mapping_row_rejects_stale_rationale_tokens_cache(self) -> None:
        """AC 21: caller-supplied cache must equal tokenize(rationale)."""
        with self.assertRaises(ValueError) as ctx:
            MappingRow(
                soc2_cc="CC6.1",
                iso_27001_2022=("A.5.15",),
                confidence="Strong",
                rationale="logical access enforcement mechanisms",
                rationale_tokens=("stale", "cache"),
                source="pin.yaml",
                row_index=3,
            )
        self.assertIn("pin.yaml: mapping row 3:", str(ctx.exception))

    def test_mapping_row_rejects_fabricated_tokens_on_blank_rationale(
        self,
    ) -> None:
        """AC 37: blank rationale cannot carry a fabricated token cache."""
        with self.assertRaises(ValueError) as ctx:
            MappingRow(
                soc2_cc="CC6.1",
                iso_27001_2022=("A.5.15",),
                confidence="Strong",
                rationale="   ",
                rationale_tokens=("logical", "access"),
                source="pin.yaml",
                row_index=1,
            )
        msg = str(ctx.exception)
        self.assertIn("pin.yaml: mapping row 1:", msg)
        self.assertIn("blank rationale", msg)

    def test_all_digit_tokens_do_not_ground(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "digit-pin.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: CC6.1\n"
                "    iso_27001_2022: [A.5.15]\n"
                "    nist_800_53: [AC-3]\n"
                "    confidence: Strong\n"
                "    rationale: >-\n"
                "      systems aligned under 27001 for customers\n",
            )
            corpus = load_corpus(path)
            question = Question(id="DIGIT", text="Are you aligned to 27001?")
            self.assertNotIn("27001", tokenize(question.text))
            self.assertTrue(retrieve(question, corpus).is_empty)

    def test_rationale_only_row_document_abstains_on_id_field_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "id-only-pin.yaml"
            _write(
                path,
                "metadata:\n  version: '1.0'\n  row_count: 1\n"
                "mappings:\n"
                "  - soc2_cc: zzzz wwww\n"
                "    iso_27001_2022: [widgetref otheriso]\n"
                "    nist_800_53: [yyyy xxxx]\n"
                "    confidence: Strong\n"
                "    rationale: neutral placeholder text here.\n",
            )
            corpus = load_corpus(path)
            question = Question(
                id="ID-ONLY",
                text=(
                    "Describe zzzz wwww widgetref otheriso yyyy xxxx controls"
                ),
            )
            self.assertTrue(retrieve(question, corpus).is_empty)

    def test_score_question_against_row_reports_sorted_matched_tokens(self) -> None:
        """AC 50: exact matched tuple; threshold compared to literal 2."""
        row = _row_by_soc2(self.corpus, "CC6.1", nist="AC-3")
        score, matched, security_count = score_question_against_row(
            self.questions["Q1"], row
        )
        self.assertGreaterEqual(score, 2)
        self.assertEqual(
            matched, ("access", "enforce", "logical", "system")
        )
        self.assertGreaterEqual(security_count, MIN_SECURITY_TOKENS)

    def test_corpus_row_tokens_cached_at_load(self) -> None:
        row = _row_by_soc2(self.corpus, "CC6.1", nist="AC-3")
        self.assertGreater(len(row.rationale_tokens), 0)
        self.assertIn("access", row.rationale_tokens)


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
                "    rationale: widget access marker\n",
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
                "    rationale: ' widget access marker '\n",
            )
            row = load_corpus(path).mappings[0]
            self.assertEqual(row.confidence, "Strong")
            self.assertEqual(row.soc2_cc, "CC6.1")
            self.assertEqual(row.rationale, "widget access marker")
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
                "    rationale: widget access marker\n",
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


class ExitCodeContractTests(unittest.TestCase):
    """Issue #7: main() exits only 0, 1, or 2."""

    def test_missing_questionnaire_exits_2(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "respond.py")],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"usage:", result.stderr)
        self.assertIn(b"\n", result.stderr)
        self.assertNotIn(b"\\x0a", result.stderr)

    def test_unknown_flag_esc_byte_not_on_stderr(self) -> None:
        evil = "--" + chr(27) + "[31mEVIL"
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "respond.py"),
                "--questionnaire",
                str(SAMPLE),
                evil,
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(bytes([27]), result.stderr)
        self.assertIn(b"unrecognized arguments", result.stderr)

    def test_broken_pipe_to_head_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            qfile = tmp_path / "many.yaml"
            # Long lines so n=400 overflows the ~64KiB pipe before the loop ends.
            _write_large_questionnaire(qfile, n=400, text="x" * 200)
            out_dir = tmp_path / "out"
            err_file = tmp_path / "stderr.txt"
            out_file = tmp_path / "stdout.txt"
            code_file = tmp_path / "code.txt"
            script = (
                "set +o pipefail\n"
                '"$1" "$2" --questionnaire "$3" --out-dir "$4" 2>"$5"'
                ' | head -3 >"$6"\n'
                'printf "%s\\n" "${PIPESTATUS[0]}" >"$7"\n'
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "_",
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    str(qfile),
                    str(out_dir),
                    str(err_file),
                    str(out_file),
                    str(code_file),
                ],
                cwd=str(REPO_ROOT),
                check=True,
                timeout=60,
            )
            code = int(code_file.read_text().strip())
            stdout = out_file.read_bytes()
            stderr = err_file.read_bytes()
            self.assertEqual(code, 0, msg=stderr.decode("utf-8", "replace"))
            self.assertEqual(stdout.count(b"\n"), 3)
            self.assertEqual(stderr, b"")
            self.assertNotIn(b"Exception ignored", stderr)
            self.assertTrue((out_dir / "responses.md").is_file())
            self.assertTrue((out_dir / "responses.json").is_file())

    def test_dev_full_exits_1(self) -> None:
        """Small questionnaire: only the final flush hits /dev/full."""
        if not os.path.exists("/dev/full"):
            self.skipTest("/dev/full is not available on this host")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with open("/dev/full", "wb") as full:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(REPO_ROOT / "respond.py"),
                        "--questionnaire",
                        str(SAMPLE),
                        "--out-dir",
                        str(out_dir),
                    ],
                    cwd=str(REPO_ROOT),
                    stdout=full,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=60,
                )
        self.assertEqual(result.returncode, 1)
        err = result.stderr.decode("utf-8", "replace")
        self.assertTrue(
            any(line.startswith("error:") for line in err.splitlines()),
            msg=err,
        )
        self.assertIn("cannot write to stdout", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Exception ignored", err)

    def test_dev_full_large_run_exits_1(self) -> None:
        """Mid-loop implicit flush on a large run still names stdout."""
        if not os.path.exists("/dev/full"):
            self.skipTest("/dev/full is not available on this host")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            qfile = tmp_path / "many.yaml"
            _write_large_questionnaire(qfile)
            out_dir = tmp_path / "out"
            with open("/dev/full", "wb") as full:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(REPO_ROOT / "respond.py"),
                        "--questionnaire",
                        str(qfile),
                        "--out-dir",
                        str(out_dir),
                    ],
                    cwd=str(REPO_ROOT),
                    stdout=full,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=60,
                )
        self.assertEqual(result.returncode, 1)
        err = result.stderr.decode("utf-8", "replace")
        self.assertIn("cannot write to stdout", err)
        self.assertNotIn("Exception ignored", err)

    def test_warning_to_closed_stderr_pipe_still_writes_drafts(self) -> None:
        """A dead stderr pipe must not abort the run: exit 0 has to mean drafts exist.

        SAMPLE emits one warning (Q6 blank text). Before the fix that warning
        went through a raw print(file=sys.stderr) inside main()'s try, so the
        BrokenPipeError landed on the return-0 backstop and the run exited 0
        having written nothing.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "out"
            code_file = tmp_path / "code.txt"
            script = (
                "set +o pipefail\n"
                '"$1" "$2" --questionnaire "$3" --out-dir "$4" 2>&1 >/dev/null'
                ' | head -0 >/dev/null\n'
                'printf "%s\\n" "${PIPESTATUS[0]}" >"$5"\n'
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "_",
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    str(SAMPLE),
                    str(out_dir),
                    str(code_file),
                ],
                cwd=str(REPO_ROOT),
                check=True,
                timeout=60,
            )
            self.assertEqual(int(code_file.read_text().strip()), 0)
            self.assertTrue((out_dir / "responses.md").is_file())
            self.assertTrue((out_dir / "responses.json").is_file())

    def test_merged_stderr_into_closed_pipe_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            err_file = tmp_path / "merged.txt"
            code_file = tmp_path / "code.txt"
            script = (
                "set +o pipefail\n"
                '"$1" "$2" --questionnaire /nope.yaml 2>&1 | head -0 >"$3"\n'
                'printf "%s\\n" "${PIPESTATUS[0]}" >"$4"\n'
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "_",
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    str(err_file),
                    str(code_file),
                ],
                cwd=str(REPO_ROOT),
                check=True,
                timeout=30,
            )
            code = int(code_file.read_text().strip())
            self.assertEqual(code, 1)
            self.assertNotIn(b"Exception ignored", err_file.read_bytes())

    def test_help_to_closed_pipe_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            err_file = tmp_path / "stderr.txt"
            code_file = tmp_path / "code.txt"
            script = (
                "set +o pipefail\n"
                '"$1" "$2" --help 2>"$3" | true\n'
                'printf "%s\\n" "${PIPESTATUS[0]}" >"$4"\n'
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "_",
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    str(err_file),
                    str(code_file),
                ],
                cwd=str(REPO_ROOT),
                check=True,
                timeout=30,
            )
            code = int(code_file.read_text().strip())
            stderr = err_file.read_bytes()
            self.assertEqual(code, 0, msg=stderr.decode("utf-8", "replace"))
            self.assertNotIn(b"Exception ignored", stderr)
            self.assertNotIn(b"Traceback", stderr)

    def test_help_prints_usage_to_stdout(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "respond.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"usage:", result.stdout)
        self.assertIn(b"\n", result.stdout)
        self.assertGreater(len(result.stdout), 100)
        self.assertNotIn(b"\\x0a", result.stdout)

    def test_closed_stdout_fd_successful_run_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "out"
            err_file = tmp_path / "err.txt"
            code_file = tmp_path / "code.txt"
            script = (
                '"$1" "$2" --questionnaire "$3" --out-dir "$4" >&- 2>"$5"\n'
                'printf "%s\\n" "$?" >"$6"\n'
            )
            subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "_",
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    str(SAMPLE),
                    str(out_dir),
                    str(err_file),
                    str(code_file),
                ],
                cwd=str(REPO_ROOT),
                check=True,
                timeout=30,
            )
            code = int(code_file.read_text().strip())
            err = err_file.read_text(encoding="utf-8", errors="replace")
            self.assertEqual(code, 0, msg=err)
            self.assertNotIn("internal error", err)
            self.assertTrue((out_dir / "responses.md").is_file())
            self.assertTrue((out_dir / "responses.json").is_file())

    def test_keyboard_interrupt_in_process_exits_1(self) -> None:
        err = io.StringIO()
        old_err = sys.stderr
        with mock.patch(
            "respond.parse_questionnaire", side_effect=KeyboardInterrupt
        ):
            try:
                sys.stderr = err
                code = main(["--questionnaire", str(SAMPLE)])
            finally:
                sys.stderr = old_err
        text = err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("error: interrupted", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("/home/", text)

    def test_sigint_mid_run_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            qfile = tmp_path / "many.yaml"
            _write_large_questionnaire(qfile)
            out_dir = tmp_path / "out"
            env = {**os.environ, "PYTHONUNBUFFERED": "1"}
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(REPO_ROOT / "respond.py"),
                    "--questionnaire",
                    str(qfile),
                    "--out-dir",
                    str(out_dir),
                ],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                line = proc.stdout.readline() if proc.stdout else b""
                if not line:
                    proc.kill()
                    self.fail("no stdout before SIGINT")
                proc.send_signal(signal.SIGINT)
                _stdout, stderr = proc.communicate(timeout=15)
            except Exception:
                proc.kill()
                raise
            err = stderr.decode("utf-8", "replace")
            self.assertEqual(proc.returncode, 1, msg=err)
            self.assertIn("error: interrupted", err)
            self.assertNotIn("Traceback", err)
            self.assertNotIn("/home/", err)

    def test_readme_exit_codes_are_exactly_0_1_2(self) -> None:
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        section = text.split("## Usage", 1)[1].split(
            "## Questionnaire schema", 1
        )[0]
        self.assertIn("`0`", section)
        self.assertIn("`1`", section)
        self.assertIn("`2`", section)
        self.assertNotIn("`120`", section)
        self.assertNotIn("`130`", section)


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
