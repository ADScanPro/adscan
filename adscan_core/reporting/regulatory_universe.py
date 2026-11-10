"""The requirement universes of DORA and NIS2, and the share an assessment evidences.

Why this module exists
----------------------
A coverage figure is only honest when the DENOMINATOR is established apart from
the NUMERATOR. ENS has had that separation for a while: the 73 measures of Anexo
II of RD 311/2022 are transcribed in
:mod:`adscan_core.reporting.ens_applicability`, and the measures the report
engine maps are a named subset of them.

DORA and NIS2 had no such separation. For both, the engine's requirement
dictionary WAS the list of what the engine maps, so any coverage computed from
it returned N of N and informed nobody. This module is the missing denominator,
transcribed from the official text, with one row per requirement and a per-row
citation.

The scoping rule
----------------
    The denominator is the set of requirements whose subject matter an identity
    and directory assessment can produce evidence about.

Four blocks fall outside it by name rather than by silence: notification to
competent authorities (deadlines, templates, channels), contractual
requirements with third-party ICT providers, governance of the testing
programme including threat-led penetration testing, and information-sharing
arrangements. A requirement whose principal subject is capacity, continuity,
physical security, training or the documentation of a process also falls
outside, under the rule's primary clause, without belonging to any of the four
named blocks.

The rule judges the PRINCIPAL subject of a requirement, never an incidental
clause inside it. Read loosely, "can produce evidence about its subject matter"
admits almost everything and the denominator stops discriminating.

Granularity
-----------
**DORA: the article, with Article 9 decomposed into its paragraphs and
paragraph 9(4) into its six points.** Thirty units. At pure article level the
universe collapses to four articles that the engine already maps in full, so the
figure returns to 100 percent and says nothing. Article 9 carries the whole
identity and access surface of the Regulation on its own, and its six points
cover unrelated control families. The Regulation itself treats those points as
separate requirements: Article 15(b) instructs the ESAs to develop "further
components of the controls of access management rights referred to in Article
9(4), point (c)". A unit the legislator cites alone is a unit.

**NIS2: the ten points of Article 21(2) of the Directive.** Deliberately NOT the
Annex of Implementing Regulation (EU) 2024/2690: its Article 1 limits that act
to eleven provider types and excludes banking, energy, transport, health, water
and public administration, which are most essential and important entities. A
denominator that does not apply to the reader is the wrong denominator. The
Annex remains the right basis for a SECTORAL figure addressed to those eleven
provider types, labelled as such, and it is not transcribed here.

Article 21(2) opens with "shall include **at least** the following", so the ten
points are a floor and a national transposition may add to them. Any text built
from this module says "the ten points of Article 21(2) of the Directive" and
never "the requirements of NIS2".

Two axes, kept apart
--------------------
**Scope** answers whether a requirement belongs in the denominator at all:
:data:`SCOPE_IN`, :data:`SCOPE_OUT`, :data:`SCOPE_UNDETERMINED`. It is a
property of the requirement against the rule, so it lives here with the
transcription.

**Evidence state** answers what this engine does about a requirement that is in
the denominator: :data:`EVIDENCE_FULL`, :data:`EVIDENCE_PARTIAL`,
:data:`EVIDENCE_NONE`. It is a property of the engine, so the mapped set and the
partial register are passed IN and never held here.

:data:`EVIDENCE_PARTIAL` is a first-class state and is never folded into either
of the other two. Some requirements are indivisible and group one branch an
assessment reaches with others it does not: Article 9(4)(f) of DORA obliges
documented patch policies while the patch state of a domain controller is
observable; point (e) of NIS2 groups acquisition and development with
vulnerability handling; point (h) groups the entity's whole cryptography policy
with the Kerberos encryption types and directory transport protection an
assessment reads. Counting those as evidenced claims the requirement; counting
them as unevidenced discards real evidence. They enter the denominator, carry
the branch they evidence and the subject they do not, and stay out of the
numerator.

:data:`SCOPE_UNDETERMINED` carries the same conservative direction for a
requirement whose place the primary text does not settle: it enters the
denominator and never the numerator, because a larger denominator can only lower
the figure.

Pure logic: stdlib only, no IO, no console, no network, importable anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

#: The requirement belongs in the denominator.
SCOPE_IN = "in_scope"

#: The requirement falls outside the denominator. The row names which block
#: excludes it, or the rule's primary clause, and says of what subject.
SCOPE_OUT = "out_of_scope"

#: The primary text does not settle where the requirement belongs. It enters the
#: denominator and never the numerator, and the row carries the open question.
SCOPE_UNDETERMINED = "scope_undetermined"

SCOPE_CLASSES = (SCOPE_IN, SCOPE_OUT, SCOPE_UNDETERMINED)

#: Every scope class that counts toward the denominator.
DENOMINATOR_SCOPES = (SCOPE_IN, SCOPE_UNDETERMINED)

#: The engine maps an observation that evidences the requirement.
EVIDENCE_FULL = "evidenced"

#: The requirement is indivisible and the engine evidences one named branch of
#: it. In the denominator, never in the numerator.
EVIDENCE_PARTIAL = "partially_evidenced"

#: The requirement is in the denominator and the engine maps nothing to it.
EVIDENCE_NONE = "not_evidenced"

EVIDENCE_STATES = (EVIDENCE_FULL, EVIDENCE_PARTIAL, EVIDENCE_NONE)

#: Notification to competent authorities: recipients, templates and deadlines.
BLOCK_AUTHORITY_REPORTING = "authority_reporting"

#: Contractual requirements with third-party ICT providers.
BLOCK_THIRD_PARTY_CONTRACTS = "third_party_contracts"

#: Governance of the testing programme, including threat-led penetration testing.
BLOCK_TESTING_GOVERNANCE = "testing_programme_governance"

#: Information-sharing arrangements on cyber threat information.
BLOCK_INFORMATION_SHARING = "information_sharing"

#: The rule's primary clause: the principal subject is not one an identity and
#: directory assessment can produce evidence about.
BLOCK_PRIMARY_CLAUSE = "primary_clause"

#: What each exclusion block is, in the words a client reads.
EXCLUDED_BLOCK_LABELS: dict[str, str] = {
    BLOCK_AUTHORITY_REPORTING: (
        "Notification to a competent authority, including the recipient, the "
        "template and the deadline"
    ),
    BLOCK_THIRD_PARTY_CONTRACTS: (
        "Contractual requirements with third-party ICT providers"
    ),
    BLOCK_TESTING_GOVERNANCE: (
        "Governance of the testing programme, including threat-led penetration "
        "testing"
    ),
    BLOCK_INFORMATION_SHARING: (
        "Information-sharing arrangements on cyber threat information"
    ),
    BLOCK_PRIMARY_CLAUSE: (
        "The requirement's principal subject is one no reading of a directory "
        "can evidence"
    ),
}


@dataclass(frozen=True)
class RequirementUnit:
    """One requirement of a framework, classified against the scoping rule.

    Attributes:
        unit_id: The engine's key for the requirement.
        reference: The citation a client and their auditor recognise.
        title: The official title of the article or point.
        grouping: Where the requirement sits in the act (a DORA chapter, or the
            paragraph a NIS2 point belongs to).
        scope: One of :data:`SCOPE_CLASSES`.
        citation: The operative sentence of the official text that decided the
            classification, quoted rather than summarised.
        reason: Why the requirement is where it is. Required for an excluded or
            undetermined row, because an exclusion stated without a reason reads
            as an omission.
        excluded_block: For an excluded row, which block of the rule excludes
            it. One of :data:`EXCLUDED_BLOCK_LABELS`.
        open_question: For an undetermined row, the decision that would settle
            it.
    """

    unit_id: str
    reference: str
    title: str
    grouping: str
    scope: str
    citation: str
    reason: str = ""
    excluded_block: str = ""
    open_question: str = ""

    @property
    def counts_toward_denominator(self) -> bool:
        """Whether this requirement is part of the published denominator."""
        return self.scope in DENOMINATOR_SCOPES


#: The thirty units of Regulation (EU) 2022/2554 (DORA), in the order the
#: Regulation introduces them.
#:
#: The 64 articles of the Regulation are not 64 requirements. Most address the
#: ESAs, the Commission, the Lead Overseer or the Member States, or amend other
#: regulations, which is the machinery of the framework rather than an
#: obligation on the entity. Twenty-two articles carry obligations on the
#: financial entity, and those are the candidates classified below, with Article
#: 9 decomposed as the module docstring explains.
#:
#: Citations are the English version of the Official Journal. Verified against
#: the Publications Office repository on 2026-10-13: the act carries no
#: amendment and no consolidated version, and none of its nine corrigenda has an
#: English version, so the text quoted here is the original.
DORA_UNITS: tuple[RequirementUnit, ...] = (
    RequirementUnit(
        unit_id="art_5",
        reference="Art. 5",
        title="Governance and organisation",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "The management body of the financial entity shall define, approve, "
            "oversee and be responsible for the implementation of all "
            "arrangements related to the ICT risk management framework."
        ),
        reason=(
            "The principal subject is accountability of the management body: "
            "approval, budget and reporting lines. The evidence is a decision "
            "or a minute, which no reading of a directory produces. Article "
            "5(2)(b) does oblige policies for the confidentiality and integrity "
            "of data, and a validated attack path shows those policies are not "
            "effective, so that clause is covered by the protection "
            "requirements of Article 9 rather than by the act of the body."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_6",
        reference="Art. 6",
        title="ICT risk management framework",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "to ensure that all information assets and ICT assets are "
            "adequately protected from risks including damage and unauthorised "
            "access or usage"
        ),
    ),
    RequirementUnit(
        unit_id="art_7",
        reference="Art. 7",
        title="ICT systems, protocols and tools",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "equipped with sufficient capacity to accurately process the data "
            "necessary for the performance of activities"
        ),
        reason=(
            "The principal subject is the suitability, reliability, capacity "
            "and technological resilience of the systems, which is capacity and "
            "performance engineering."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_8",
        reference="Art. 8",
        title="Identification",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "They shall map the configuration of the information assets and ICT "
            "assets and the links and interdependencies between the different "
            "information assets and ICT assets."
        ),
    ),
    RequirementUnit(
        unit_id="art_9_1",
        reference="Art. 9(1)",
        title="Protection and prevention: continuous monitoring and control",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "financial entities shall continuously monitor and control the "
            "security and functioning of ICT systems and tools"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_2",
        reference="Art. 9(2)",
        title="Protection and prevention: ICT security policies, procedures, protocols and tools",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "shall design, procure and implement ICT security policies, "
            "procedures, protocols and tools that aim to ensure the resilience, "
            "continuity and availability of ICT systems"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_3",
        reference="Art. 9(3)",
        title="Protection and prevention: properties of ICT solutions and processes",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "minimise the risk of corruption or loss of data, unauthorised "
            "access and technical flaws that may hinder business activity"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_4_a",
        reference="Art. 9(4)(a)",
        title="Information security policy",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "develop and document an information security policy defining rules "
            "to protect the availability, authenticity, integrity and "
            "confidentiality of data, information assets and ICT assets"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_4_b",
        reference="Art. 9(4)(b)",
        title="Network and infrastructure management structure",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "establish a sound network and infrastructure management structure "
            "using appropriate techniques, methods and protocols"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_4_c",
        reference="Art. 9(4)(c)",
        title="Logical access limitation and administration of access rights",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "implement policies that limit the physical or logical access to "
            "information assets and ICT assets to what is required for "
            "legitimate and approved functions and activities only, and "
            "establish to that end a set of policies, procedures and controls "
            "that address access rights and ensure a sound administration thereof"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_4_d",
        reference="Art. 9(4)(d)",
        title="Strong authentication mechanisms and protection of cryptographic keys",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "implement policies and protocols for strong authentication "
            "mechanisms, based on relevant standards and dedicated control "
            "systems, and protection measures of cryptographic keys"
        ),
    ),
    RequirementUnit(
        unit_id="art_9_4_e",
        reference="Art. 9(4)(e)",
        title="ICT change management",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "implement documented policies, procedures and controls for ICT "
            "change management, including changes to software, hardware, "
            "firmware components, systems or security parameters"
        ),
        reason="The principal subject is change management.",
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_9_4_f",
        reference="Art. 9(4)(f)",
        title="Policies for patches and updates",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "have appropriate and comprehensive documented policies for patches "
            "and updates"
        ),
        reason=(
            "The obligation is to hold documented policies, which is a "
            "document. The patch state those policies have to produce on a "
            "domain controller is observable, and an assessment reads it, so "
            "the requirement is in the denominator with one branch evidenced "
            "and the policy itself unevidenced."
        ),
    ),
    RequirementUnit(
        unit_id="art_10",
        reference="Art. 10",
        title="Detection",
        grouping="Chapter II",
        scope=SCOPE_IN,
        citation=(
            "shall have in place mechanisms to promptly detect anomalous "
            "activities, in accordance with Article 17, including ICT network "
            "performance issues and ICT-related incidents, and to identify "
            "potential material single points of failure"
        ),
    ),
    RequirementUnit(
        unit_id="art_11",
        reference="Art. 11",
        title="Response and recovery",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "shall put in place a comprehensive ICT business continuity policy"
        ),
        reason=(
            "The principal subject is business continuity: the continuity "
            "policy, the business impact analysis required by Article 11(5), "
            "the recovery plans and their testing. Article 11(2)(c) names "
            "containment measures, and the subject of the article is still "
            "continuity."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_12",
        reference="Art. 12",
        title="Backup policies and procedures, restoration and recovery",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "backup policies and procedures specifying the scope of the data "
            "that is subject to the backup and the minimum frequency of the "
            "backup"
        ),
        reason="The principal subject is backup and restoration.",
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_13",
        reference="Art. 13",
        title="Learning and evolving",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "shall develop ICT security awareness programmes and digital "
            "operational resilience training"
        ),
        reason=(
            "The principal subject is post-incident review, lessons learned and "
            "staff training."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_14",
        reference="Art. 14",
        title="Communication",
        grouping="Chapter II",
        scope=SCOPE_OUT,
        citation=(
            "shall have in place crisis communication plans enabling a "
            "responsible disclosure of, at least, major ICT-related incidents "
            "or vulnerabilities to clients and counterparts as well as to the "
            "public"
        ),
        reason="The principal subject is crisis communication.",
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_16",
        reference="Art. 16",
        title="Simplified ICT risk management framework",
        grouping="Chapter II",
        scope=SCOPE_UNDETERMINED,
        citation=(
            "Articles 5 to 15 of this Regulation shall not apply to small and "
            "non-interconnected investment firms"
        ),
        reason=(
            "The article replaces Articles 5 to 15 for a closed set of smaller "
            "entities and restates the same control objectives at lower "
            "intensity. Counting it alongside those articles doubles one "
            "subject for a second population; leaving it out leaves those "
            "entities with no applicable requirement."
        ),
        open_question=(
            "Whether the denominator is stated per population of entity or as "
            "the union of all of them. Against a single entity the article "
            "replaces Articles 5 to 15 rather than adding to them."
        ),
    ),
    RequirementUnit(
        unit_id="art_17",
        reference="Art. 17",
        title="ICT-related incident management process",
        grouping="Chapter III",
        scope=SCOPE_OUT,
        citation=(
            "shall define, establish and implement an ICT-related incident "
            "management process to detect, manage and notify ICT-related "
            "incidents"
        ),
        reason=(
            "The principal subject is the incident management process, with its "
            "roles, escalation and internal communication. Its one observable "
            "branch is detection, and detection is already Article 10, which is "
            "in the denominator, so the detection evidence an assessment "
            "produces belongs there."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_18",
        reference="Art. 18",
        title="Classification of ICT-related incidents and cyber threats",
        grouping="Chapter III",
        scope=SCOPE_OUT,
        citation=(
            "the number and relevance of clients or financial counterparts "
            "affected and, where applicable, the amount or number of "
            "transactions affected"
        ),
        reason="The principal subject is a methodology for classifying impact.",
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="art_19",
        reference="Art. 19",
        title=(
            "Reporting of major ICT-related incidents and voluntary "
            "notification of significant cyber threats"
        ),
        grouping="Chapter III",
        scope=SCOPE_OUT,
        citation=(
            "Financial entities shall report major ICT-related incidents to the "
            "relevant competent authority as referred to in Article 46 [...] "
            "using the templates referred to in Article 20 [...] within the "
            "time limits to be laid down in accordance with Article 20."
        ),
        reason=(
            "All three elements the excluded block names are in the text of the "
            "article itself: the competent authority that receives the report, "
            "the template it is filed on, and the deadline. No assessment of a "
            "directory can evidence that an entity notified its authority on "
            "time and on the template."
        ),
        excluded_block=BLOCK_AUTHORITY_REPORTING,
    ),
    RequirementUnit(
        unit_id="art_24",
        reference="Art. 24",
        title=(
            "General requirements for the performance of digital operational "
            "resilience testing"
        ),
        grouping="Chapter IV",
        scope=SCOPE_OUT,
        citation=(
            "shall establish, maintain and review a sound and comprehensive "
            "digital operational resilience testing programme"
        ),
        reason=(
            "Establishing, maintaining and reviewing the programme, and the "
            "independence of the testers, is the governance of the testing "
            "programme."
        ),
        excluded_block=BLOCK_TESTING_GOVERNANCE,
    ),
    RequirementUnit(
        unit_id="art_25",
        reference="Art. 25",
        title="Testing of ICT tools and systems",
        grouping="Chapter IV",
        scope=SCOPE_UNDETERMINED,
        citation=(
            "vulnerability assessments and scans, open source analyses, network "
            "security assessments, gap analyses, physical security reviews, "
            "questionnaires and scanning software solutions, source code "
            "reviews where feasible, scenario-based tests, compatibility "
            "testing, performance testing, end-to-end testing and penetration "
            "testing"
        ),
        reason=(
            "The excluded block covers the GOVERNANCE of the testing "
            "programme, which Article 24 and the threat-led articles exhaust. "
            "Article 25 is the CONTENT of the programme, and the types of test "
            "its first paragraph enumerates include network security "
            "assessments and penetration testing. An ADscan assessment is one "
            "of the named types."
        ),
        open_question=(
            "Whether evidence of having performed a named type of test counts "
            "toward Article 25(1), or only the programme document counts."
        ),
    ),
    RequirementUnit(
        unit_id="art_26",
        reference="Art. 26",
        title=(
            "Advanced testing of ICT tools, systems and processes based on TLPT"
        ),
        grouping="Chapter IV",
        scope=SCOPE_OUT,
        citation=(
            "shall carry out at least every 3 years advanced testing by means "
            "of TLPT"
        ),
        reason="Threat-led penetration testing and its governance.",
        excluded_block=BLOCK_TESTING_GOVERNANCE,
    ),
    RequirementUnit(
        unit_id="art_27",
        reference="Art. 27",
        title="Requirements for testers for the carrying out of TLPT",
        grouping="Chapter IV",
        scope=SCOPE_OUT,
        citation=(
            "Financial entities shall only use testers for the carrying out of "
            "TLPT that [...] are of the highest suitability and reputability"
        ),
        reason="The suitability of the testers of a threat-led test.",
        excluded_block=BLOCK_TESTING_GOVERNANCE,
    ),
    RequirementUnit(
        unit_id="art_28",
        reference="Art. 28",
        title="ICT third-party risk: general principles",
        grouping="Chapter V",
        scope=SCOPE_OUT,
        citation=(
            "shall manage ICT third-party risk as an integral component of ICT "
            "risk"
        ),
        reason="Third-party ICT provider arrangements.",
        excluded_block=BLOCK_THIRD_PARTY_CONTRACTS,
    ),
    RequirementUnit(
        unit_id="art_29",
        reference="Art. 29",
        title=(
            "Preliminary assessment of ICT concentration risk at entity level"
        ),
        grouping="Chapter V",
        scope=SCOPE_OUT,
        citation=(
            "shall take into account whether the envisaged conclusion of a "
            "contractual arrangement [...] would lead to [...] ICT "
            "concentration risk"
        ),
        reason="Concentration risk in third-party contractual arrangements.",
        excluded_block=BLOCK_THIRD_PARTY_CONTRACTS,
    ),
    RequirementUnit(
        unit_id="art_30",
        reference="Art. 30",
        title="Key contractual provisions",
        grouping="Chapter V",
        scope=SCOPE_OUT,
        citation=(
            "The rights and obligations of the financial entity and of the ICT "
            "third-party service provider shall be clearly allocated and set "
            "out in writing."
        ),
        reason="The contractual provisions themselves.",
        excluded_block=BLOCK_THIRD_PARTY_CONTRACTS,
    ),
    RequirementUnit(
        unit_id="art_45",
        reference="Art. 45",
        title=(
            "Information-sharing arrangements on cyber threat information and "
            "intelligence"
        ),
        grouping="Chapter VI",
        scope=SCOPE_OUT,
        citation=(
            "Financial entities may exchange amongst themselves cyber threat "
            "information and intelligence"
        ),
        reason="Information-sharing arrangements.",
        excluded_block=BLOCK_INFORMATION_SHARING,
    ),
)


#: The ten points of Article 21(2) of Directive (EU) 2022/2555 (NIS2), in the
#: order the Directive introduces them. Verified against the English version of
#: the Official Journal on 2026-10-13: the list is closed, runs from (a) to (j)
#: with no letter omitted, and the one corrigendum with an English version
#: corrects a word of Article 19(1) and does not touch Article 21.
NIS2_UNITS: tuple[RequirementUnit, ...] = (
    RequirementUnit(
        unit_id="21.2.a",
        reference="Art. 21(2)(a)",
        title="Risk analysis and information system security policies",
        grouping="Article 21(2)",
        scope=SCOPE_OUT,
        citation="policies on risk analysis and information system security",
        reason=(
            "The principal subject is the policy artefact and the risk "
            "analysis. The evidence is an approved document, which no reading "
            "of a directory produces."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="21.2.b",
        reference="Art. 21(2)(b)",
        title="Incident handling",
        grouping="Article 21(2)",
        scope=SCOPE_OUT,
        citation="incident handling",
        reason=(
            "The principal subject is the incident handling process. Its one "
            "observable branch is monitoring and logging, which point (f) "
            "already covers from the angle of effectiveness."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="21.2.c",
        reference="Art. 21(2)(c)",
        title="Business continuity and crisis management",
        grouping="Article 21(2)",
        scope=SCOPE_OUT,
        citation=(
            "business continuity, such as backup management and disaster "
            "recovery, and crisis management"
        ),
        reason=(
            "The principal subject is continuity, backup, recovery and crisis "
            "management."
        ),
        excluded_block=BLOCK_PRIMARY_CLAUSE,
    ),
    RequirementUnit(
        unit_id="21.2.d",
        reference="Art. 21(2)(d)",
        title="Supply chain security",
        grouping="Article 21(2)",
        scope=SCOPE_OUT,
        citation=(
            "supply chain security, including security-related aspects "
            "concerning the relationships between each entity and its direct "
            "suppliers or service providers"
        ),
        reason=(
            "The point defines its own subject as the relationships with "
            "direct suppliers and service providers."
        ),
        excluded_block=BLOCK_THIRD_PARTY_CONTRACTS,
    ),
    RequirementUnit(
        unit_id="21.2.e",
        reference="Art. 21(2)(e)",
        title=(
            "Security in network and information systems acquisition, "
            "development and maintenance"
        ),
        grouping="Article 21(2)",
        scope=SCOPE_IN,
        citation=(
            "security in network and information systems acquisition, "
            "development and maintenance, including vulnerability handling and "
            "disclosure"
        ),
        reason=(
            "The point groups two subjects of opposite sign: acquisition, "
            "development and maintenance, which is a lifecycle an assessment "
            "does not observe, and vulnerability handling and disclosure, which "
            "it does. The Directive offers no finer unit, so the point enters "
            "the denominator with the branch it evidences named."
        ),
    ),
    RequirementUnit(
        unit_id="21.2.f",
        reference="Art. 21(2)(f)",
        title=(
            "Policies and procedures to assess the effectiveness of "
            "cybersecurity risk-management measures"
        ),
        grouping="Article 21(2)",
        scope=SCOPE_IN,
        citation=(
            "policies and procedures to assess the effectiveness of "
            "cybersecurity risk-management measures"
        ),
    ),
    RequirementUnit(
        unit_id="21.2.g",
        reference="Art. 21(2)(g)",
        title="Basic cyber hygiene practices and cybersecurity training",
        grouping="Article 21(2)",
        scope=SCOPE_IN,
        citation="basic cyber hygiene practices and cybersecurity training",
        reason=(
            "Training falls outside. Basic cyber hygiene does not: it reaches "
            "secure configuration and account management, which an assessment "
            "reads. The point joins the two and cannot be split."
        ),
    ),
    RequirementUnit(
        unit_id="21.2.h",
        reference="Art. 21(2)(h)",
        title="Cryptography and encryption",
        grouping="Article 21(2)",
        scope=SCOPE_IN,
        citation=(
            "policies and procedures regarding the use of cryptography and, "
            "where appropriate, encryption"
        ),
        reason=(
            "The principal subject is the entity's cryptography policy, which "
            "is wider than identity. The cryptographic controls an assessment "
            "does read, the Kerberos encryption types and the protection of "
            "directory transport, fall under this point and no narrower point "
            "collects them."
        ),
    ),
    RequirementUnit(
        unit_id="21.2.i",
        reference="Art. 21(2)(i)",
        title="Human resources security, access control policies and asset management",
        grouping="Article 21(2)",
        scope=SCOPE_IN,
        citation=(
            "human resources security, access control policies and asset "
            "management"
        ),
    ),
    RequirementUnit(
        unit_id="21.2.j",
        reference="Art. 21(2)(j)",
        title="Multi-factor authentication and secured communications",
        grouping="Article 21(2)",
        scope=SCOPE_IN,
        citation=(
            "the use of multi-factor authentication or continuous "
            "authentication solutions, secured voice, video and text "
            "communications and secured emergency communication systems within "
            "the entity, where appropriate"
        ),
    ),
)


#: Every framework whose requirement universe is transcribed here.
FRAMEWORK_UNITS: dict[str, tuple[RequirementUnit, ...]] = {
    "dora": DORA_UNITS,
    "nis2": NIS2_UNITS,
}

#: What the denominator of each framework is, in the words a client reads.
#:
#: Published beside the figure, never without it. A reader who sees "8 of 13"
#: for a Regulation of 64 articles concludes the opposite of what the data says
#: unless the sentence states that the scoping rule cuts away, on purpose, every
#: requirement no reading of a directory can evidence.
FRAMEWORK_DENOMINATOR_BASIS: dict[str, str] = {
    "dora": (
        "The denominator is the requirements of Regulation (EU) 2022/2554 whose "
        "subject matter an identity and directory assessment can produce "
        "evidence about, read at the level of the article with Article 9 "
        "decomposed into its paragraphs and paragraph 9(4) into its six points. "
        "Requirements outside it are listed with the reason, because an "
        "assessment of a directory cannot evidence a notification to an "
        "authority, a provider contract, the governance of a testing programme, "
        "or a subject such as continuity, physical security or training."
    ),
    "nis2": (
        "The denominator is the ten points of Article 21(2) of Directive (EU) "
        "2022/2555 whose subject matter an identity and directory assessment "
        "can produce evidence about. Article 21(2) requires that the measures "
        "include at least those ten points, so a national transposition may add "
        "to them and the figure speaks to the Directive's own list. The "
        "technical requirements of Implementing Regulation (EU) 2024/2690 are a "
        "separate and narrower basis: its Article 1 applies it to eleven types "
        "of provider, so a figure built on it would not apply to a bank, an "
        "energy operator or a hospital."
    ),
}


def framework_units(framework: str) -> tuple[RequirementUnit, ...]:
    """Return one framework's transcribed requirement universe.

    Args:
        framework: A key of :data:`FRAMEWORK_UNITS`.

    Returns:
        Every unit of the framework in normative order, or an empty tuple when
        the framework has no transcribed universe.
    """
    return FRAMEWORK_UNITS.get(framework, ())


def unit_ids(framework: str) -> tuple[str, ...]:
    """Return one framework's unit ids, in normative order."""
    return tuple(unit.unit_id for unit in framework_units(framework))


def denominator_ids(framework: str) -> tuple[str, ...]:
    """Return the unit ids that count toward the published denominator."""
    return tuple(
        unit.unit_id
        for unit in framework_units(framework)
        if unit.counts_toward_denominator
    )


def resolve_evidence_state(
    unit: RequirementUnit,
    *,
    mapped_ids: Iterable[str],
    partial_ids: Iterable[str],
) -> str:
    """Return the evidence state of one unit, or an empty string when excluded.

    An excluded unit has no evidence state: it is not in the denominator, so
    there is nothing for the engine to be measured against. A unit named in
    ``partial_ids`` resolves to :data:`EVIDENCE_PARTIAL` whether or not it is
    mapped, because the partial register is the statement that the mapping
    reaches one branch of an indivisible requirement.
    """
    if not unit.counts_toward_denominator:
        return ""
    if unit.unit_id in set(partial_ids):
        return EVIDENCE_PARTIAL
    return EVIDENCE_FULL if unit.unit_id in set(mapped_ids) else EVIDENCE_NONE


def build_requirement_coverage(
    framework: str,
    *,
    mapped_ids: Iterable[str],
    partial_evidence: Mapping[str, Mapping[str, str]] | None = None,
    declined_reasons: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return one framework's coverage declaration: figures plus every row.

    Args:
        framework: A key of :data:`FRAMEWORK_UNITS`.
        mapped_ids: The requirement ids the report engine maps.
        partial_evidence: Per-unit ``{"branch": ..., "unevidenced": ...}`` for
            an indivisible requirement the engine evidences in part. A unit
            named here never counts in the numerator.
        declined_reasons: Per-unit reason a requirement inside the denominator
            carries no mapping, so an absence is published with its reason
            rather than as a blank.

    Returns:
        ``figures`` (the counts and the basis sentence) and ``requirements``
        (one row per unit of the universe, in normative order). Every unit of
        the universe is a row, the excluded ones included: a list of only the
        denominator states a share with nothing to be a fraction of.
    """
    units = framework_units(framework)
    mapped = set(mapped_ids)
    partials = dict(partial_evidence or {})
    declined = dict(declined_reasons or {})

    rows: list[dict[str, object]] = []
    counts = {state: 0 for state in EVIDENCE_STATES}
    by_block: dict[str, int] = {}

    for unit in units:
        state = resolve_evidence_state(
            unit, mapped_ids=mapped, partial_ids=partials
        )
        if state:
            counts[state] += 1
        if unit.scope == SCOPE_OUT:
            block = unit.excluded_block or BLOCK_PRIMARY_CLAUSE
            by_block[block] = by_block.get(block, 0) + 1
        partial = partials.get(unit.unit_id) or {}
        rows.append(
            {
                "unit_id": unit.unit_id,
                "reference": unit.reference,
                "title": unit.title,
                "grouping": unit.grouping,
                "citation": unit.citation,
                "scope": unit.scope,
                "in_denominator": unit.counts_toward_denominator,
                "excluded_block": unit.excluded_block,
                "excluded_block_label": EXCLUDED_BLOCK_LABELS.get(
                    unit.excluded_block, ""
                ),
                "reason": unit.reason,
                "open_question": unit.open_question,
                "evidence_state": state,
                "mapped": unit.unit_id in mapped,
                "evidenced_branch": str(partial.get("branch") or ""),
                "unevidenced_subject": str(partial.get("unevidenced") or ""),
                "declined_reason": declined.get(unit.unit_id, ""),
            }
        )

    denominator = sum(counts.values())
    return {
        "framework": framework,
        "figures": {
            "universe_total": len(units),
            "denominator": denominator,
            "evidenced": counts[EVIDENCE_FULL],
            "partially_evidenced": counts[EVIDENCE_PARTIAL],
            "not_evidenced": counts[EVIDENCE_NONE],
            "out_of_scope": len(units) - denominator,
            "out_of_scope_by_block": by_block,
            "denominator_basis": FRAMEWORK_DENOMINATOR_BASIS.get(framework, ""),
        },
        "requirements": rows,
    }


__all__ = [
    "BLOCK_AUTHORITY_REPORTING",
    "BLOCK_INFORMATION_SHARING",
    "BLOCK_PRIMARY_CLAUSE",
    "BLOCK_TESTING_GOVERNANCE",
    "BLOCK_THIRD_PARTY_CONTRACTS",
    "DENOMINATOR_SCOPES",
    "DORA_UNITS",
    "EVIDENCE_FULL",
    "EVIDENCE_NONE",
    "EVIDENCE_PARTIAL",
    "EVIDENCE_STATES",
    "EXCLUDED_BLOCK_LABELS",
    "FRAMEWORK_DENOMINATOR_BASIS",
    "FRAMEWORK_UNITS",
    "NIS2_UNITS",
    "RequirementUnit",
    "SCOPE_CLASSES",
    "SCOPE_IN",
    "SCOPE_OUT",
    "SCOPE_UNDETERMINED",
    "build_requirement_coverage",
    "denominator_ids",
    "framework_units",
    "resolve_evidence_state",
    "unit_ids",
]
