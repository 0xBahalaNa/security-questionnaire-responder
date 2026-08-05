# Questionnaire responses

Corpus: corpus/mappings.yaml (version 1.0)
Coverage: 2/6 (33%)

### Q1

Describe how you enforce logical access controls for production systems.

**Status:** answered

**Criterion:** SOC 2 CC6.1

**Cross-references:** ISO 27001:2022 A.5.15, A.8.3; NIST 800-53 AC-3

**Confidence:** Strong

**Rationale:** AC-3 enforces approved authorizations for logical access at the system
and application layer. CC6.1 frames logical-access security architecture
and enforcement mechanisms. ISO A.5.15 (access control) and A.8.3
(information access restriction) address the same enforcement intent from
policy and technical restriction angles.

**Source:** corpus/mappings.yaml version 1.0

### Q2

How do you provision and authorize new user accounts before credentials are issued?

**Status:** answered

**Criterion:** SOC 2 CC6.2

**Cross-references:** ISO 27001:2022 A.5.16, A.5.18; NIST 800-53 AC-2

**Confidence:** Strong

**Rationale:** AC-2 governs the full account lifecycle — approve before create, modify,
disable, remove, and periodic review. CC6.2 covers registration and
authorization of new users before credentials are issued. ISO A.5.16
(identity management) and A.5.18 (access rights) map to provisioning
and rights assignment during onboarding.

**Source:** corpus/mappings.yaml version 1.0

### Q3

How do you enforce least privilege for administrative / privileged access?

**Status:** INSUFFICIENT_COVERAGE

**Reason:** top hits within MARGIN: CC6.3 (Strong, AC-6,AC-2) vs CC6.1 (Strong, AC-3)

**Suggested owner:** Identity & Access Management

### Q4

What authentication controls do you require for users accessing the system?

**Status:** INSUFFICIENT_COVERAGE

**Reason:** top hits within MARGIN: CC6.6 (Strong, IA-2) vs CC6.1 (Strong, AC-3)

**Suggested owner:** Identity & Access Management

### Q5

What is your data residency commitment for EU customers?

**Status:** INSUFFICIENT_COVERAGE

**Reason:** no grounded corpus match

**Suggested owner:** Privacy / Legal

### Q6

(blank)

**Status:** INSUFFICIENT_COVERAGE

**Reason:** blank question text

**Suggested owner:** Security SME (unrouted)
