#!/usr/bin/env python3
"""
KSI-CMT-LMC / FedRAMP SCN: GitLab Significant Change Notifications

Finds merge requests that engineering flagged as a FedRAMP significant change,
parses the SCN section of the MR description, and emits one FedRAMP-schema-valid
Significant Change Notification per flagged MR.

Flow:
  1. List MRs for one project in the lookback window (paginated).
  2. Keep the ones whose description carries a TICKED marker checkbox
     (`- [x] Significant Change — SCN required`), or the configured GitLab label.
  3. Slice out the SCN section and parse it two ways, in priority order:
       a. SCHEMA MARKERS — Paramify's change-request template annotates each
          field with its schema key, e.g. "**Reason for Change** *(`reason`)*".
          That annotation is authoritative: it is impossible to misread and it
          survives anyone renaming the human-facing label.
       b. HEADINGS — for templates without those annotations, `### Reason for
          Change` and `**Key:** value` lines are mapped by name. Only fills
          fields (a) did not.
  4. Assemble an SCN per MR and validate it against the vendored FedRAMP schema
     (schemas/fedramp_scn_2026-06-24.json).
  5. Write ONE evidence file holding the array of SCNs plus per-MR provenance.

Single-target per invocation; fanout across projects happens at the runner layer
(see fetcher.yaml: supports_targets: true).

Note on shape: the runner discovers evidence by diffing EVIDENCE_DIR and wraps
every .json it finds in the standard envelope. So this fetcher writes exactly one
file — N separate SCN files would each get enveloped and stop being schema-valid
FedRAMP documents. Each element of payload.notifications[].scn is a verbatim,
schema-valid SCN object that a downstream step can lift out and submit as-is.

Unfilled template placeholders (`YYYY-MM-DD`, `KSI-XXX-XXX`, `N/A`, …) are dropped
rather than emitted, and each drop is recorded in parse_notes. A notification that
says nothing is better evidence than one that says "YYYY-MM-DD".
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv
from jsonschema import Draft202012Validator, FormatChecker

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("gitlab_significant_change_notifications")

SCHEMA_PATH = Path(__file__).parent / "schemas" / "fedramp_scn_2026-06-24.json"
SCHEMA_ID = "https://fedramp.gov/schemas/fedramp-significant-change-notifications-schema-2026-06-24.json"

# --- marker + section detection -------------------------------------------------
# A ticked task-list checkbox whose label mentions a significant change / SCN.
# Tolerates -, *, +; [x] or [X]; hyphen, en dash or em dash; trailing instructions.
MARKER_RE = re.compile(
    r"^\s*[-*+]\s*\[[xX]\]\s*.*significant\s+change.*$", re.MULTILINE | re.IGNORECASE
)
# Same line UNticked — used only to tell "author saw the box and left it off"
# apart from "the template isn't installed", which is a different conversation.
UNTICKED_MARKER_RE = re.compile(
    r"^\s*[-*+]\s*\[\s*\]\s*.*significant\s+change.*$", re.MULTILINE | re.IGNORECASE
)
# The sibling checkbox: an explicit SCN-RTR "routine recurring, no notification"
# declaration. Ticking it is a decision and belongs in the audit trail.
ROUTINE_RECURRING_RE = re.compile(
    r"^\s*[-*+]\s*\[[xX]\]\s*.*routine\s+recurring.*$", re.MULTILINE | re.IGNORECASE
)
EMERGENCY_RE = re.compile(
    r"^\s*[-*+]\s*\[[xX]\]\s*.*emergency\s+change.*$", re.MULTILINE | re.IGNORECASE
)

HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<title>.+?)\s*$")
HR_RE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")
KV_RE = re.compile(r"^\s*\*\*(?P<key>[^*:]+?)\s*:?\s*\*\*\s*:?\s*(?P<value>.*)$")
BULLET_RE = re.compile(r"^\s*[-*+]\s+(?P<item>.+?)\s*$")
CHECKBOX_RE = re.compile(r"^\s*[-*+]\s*\[(?P<mark>[ xX])\]\s*(?P<label>.*?)\s*$")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
CHECKBOX_LINE_RE = re.compile(r"^\s*[-*+]\s*\[[ xX]\]\s*")
ISO_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
# Greedy on the URL so a link target containing parens — the CPO URI ends in
# "(1).json" — survives extraction.
MD_LINK_RE = re.compile(r"^\[[^\]]*\]\((?P<url>.+)\)$")
MD_LINK_ANY_RE = re.compile(r"\[(?P<text>[^\]]*)\]\([^)]*(?:\([^)]*\)[^)]*)*\)")
BACKTICK_SPAN_RE = re.compile(r"`([^`]+)`")
# `**[REQUIRED]**`, `**\[REQUIRED within planAndTimeline\]**` — annotation, not value.
BOLD_BRACKET_TOKEN_RE = re.compile(r"\*\*\s*\\?\[[^\]]*\\?\]\s*\*\*")
PARENTHETICAL_RE = re.compile(r"\((?:[^()]|\([^()]*\))*\)")
BOLD_LABEL_RE = re.compile(r"\*\*[^*]*\*\*")
# A line that is nothing but bold label(s) — `**Impact Analysis**`, `** SCN Details**`.
# In the change-request template these are grouping headers, so they end the
# preceding field rather than belonging to it.
BOLD_ONLY_LINE_RE = re.compile(r"^\s*(?:\*\*[^*]+\*\*\s*)+$")
DATE_TOKEN_RE = re.compile(r"`?\b(?:\d{4}-\d{2}-\d{2}|Y{4}-M{2}-D{2})\b`?", re.IGNORECASE)

# --- the schema-key annotation the change-request template carries ---------------
# Paramify's template writes each field as e.g.
#     **Categorization Explanation** *(`changeTypeExplanation`)*
#     **Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)*
# The backticked key is the field. Whitelisted so a stray backticked identifier
# in prose can never be mistaken for one.
KNOWN_SCHEMA_KEYS = {
    "certificationPackageOverviewUri",
    "assessorName",
    "relatedVulnerability",
    "changeType",
    "changeTypeExplanation",
    "changeDescription",
    "reason",
    "customerImpact",
    "impactAnalysis",
    "impactedControls",
    "planAndTimeline",
    "planAndTimeline.summary",
    "planAndTimeline.plannedStart",
    "planAndTimeline.plannedCompletion",
    "planAndTimeline.milestones",
}
SCHEMA_MARKER_RE = re.compile(
    r"\(\s*`(?P<key>[A-Za-z][A-Za-z0-9_.]*)(?:\[\])?`\s*\)"
)

# Heading text (normalized) -> SCN field, for templates with no schema markers.
HEADING_FIELD_MAP: Dict[str, str] = {
    "description": "changeDescription",
    "change description": "changeDescription",
    "short description": "changeDescription",
    "requested changes": "changeDescription",
    "change type": "changeType",
    "change type explanation": "changeTypeExplanation",
    "categorization explanation": "changeTypeExplanation",
    "reason": "reason",
    "reason for change": "reason",
    "customer impact": "customerImpact",
    "impact analysis": "impactAnalysis",
    "business or security impact analysis": "impactAnalysis",
    "security impact analysis": "impactAnalysis",
    "impact and security analysis": "impactAnalysis",
    "impacted controls": "impactedControls",
    "impacted ksis or rev5 controls": "impactedControls",
    "impacted ksis": "impactedControls",
    "plan and timeline": "planAndTimeline.summary",
    "plan": "planAndTimeline.summary",
    "timeline": "planAndTimeline.summary",
    "plan and timeline summary": "planAndTimeline.summary",
    "milestones": "planAndTimeline.milestones",
    "planned start": "planAndTimeline.plannedStart",
    "planned completion": "planAndTimeline.plannedCompletion",
    "planned end": "planAndTimeline.plannedCompletion",
    "related vulnerability": "relatedVulnerability",
    "assessor": "assessorName",
    "assessor name": "assessorName",
    "certification package overview uri": "certificationPackageOverviewUri",
}

# `**Key:** value` inline pairs -> SCN field (or payload-side provenance).
KV_FIELD_MAP: Dict[str, str] = {
    "change type": "changeType",
    "type": "changeType",
    "assessor": "assessorName",
    "assessor name": "assessorName",
    "related vulnerability": "relatedVulnerability",
    "vulnerability": "relatedVulnerability",
    "planned start": "planAndTimeline.plannedStart",
    "planned completion": "planAndTimeline.plannedCompletion",
    "planned end": "planAndTimeline.plannedCompletion",
    "certification package overview uri": "certificationPackageOverviewUri",
    # Provenance, not schema fields — SCN-CSO-INF wants an approver but the
    # FedRAMP JSON schema v0.1.2 has nowhere to put one.
    "approver": "_approver.name",
    "approver title": "_approver.title",
    "approver name": "_approver.name",
}

# --- SCN-CSO-INF: the information a notification must actually carry ------------
# FedRAMP's JSON schema requires only three properties. SCN-CSO-INF asks for far
# more, and the gap is not academic: a notification can validate perfectly while
# saying nothing about which controls the change touches, when it happens, or who
# approved it. Schema validity proves the document is well-formed; this table is
# what proves it is worth sending.
#
# "(if applicable)" items — assessorName, relatedVulnerability — are deliberately
# absent: SCN-CSO-INF conditions them, so their absence is not a defect.
SCN_CSO_INF_REQUIREMENTS: List[Tuple[str, str]] = [
    ("changeType", "change type (Adaptive or Transformative)"),
    ("changeTypeExplanation", "explanation of why the change was categorized that way"),
    ("changeDescription", "short description of the change"),
    ("reason", "reason for the change"),
    ("customerImpact", "summary of customer impact, including customer configuration responsibilities"),
    ("impactAnalysis", "business or security impact analysis"),
    ("impactedControls", "the KSIs or Rev5 controls verified, assessed or validated as part of the change"),
    ("planAndTimeline.summary", "plan and timeline summary, including the verification approach"),
    ("planAndTimeline.plannedStart", "the date changes to the system begin"),
    ("planAndTimeline.plannedCompletion", "the date the change is considered complete"),
    ("certificationPackageOverviewUri", "certification package overview URI"),
    ("_approver.name", "approver name"),
    ("_approver.title", "approver title"),
]

CHANGE_TYPE_CANON = {"adaptive": "Adaptive", "transformative": "Transformative"}

# Fields whose value is a URI and therefore arrives mangled by whatever pasted
# it: GitLab autolinks, a Markdown editor, or someone wrapping it in backticks.
URI_FIELDS = {"certificationPackageOverviewUri"}
DATE_FIELDS = {"planAndTimeline.plannedStart", "planAndTimeline.plannedCompletion"}
LIST_FIELDS = {"impactedControls"}
TEXT_FIELDS_WITH_LABEL_PREFIX = re.compile(r"^\s*(?:date|value|text)\s*:\s*", re.IGNORECASE)

# Template text nobody replaced. Emitting these is worse than emitting nothing:
# "YYYY-MM-DD" fails schema validation for a reason that tells you nothing, and
# "N/A" in an optional field is noise a reviewer has to read past.
PLACEHOLDER_RE = re.compile(
    r"""^(?:
        n\s*/?\s*a | tbd | tba | none | todo | tbc | \?+ | -+ |
        y{4}\s*-\s*m{2}\s*-\s*d{2} | mm/dd/yyyy | dd/mm/yyyy | hh:mm |
        [a-z]{2,5}-x+(?:-x+)? |
        [a-z]{2,5}-\?+ |
        x+
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def normalize(text: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace — for fuzzy heading match."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).split())


def normalize_heading(title: str) -> str:
    """Heading text -> HEADING_FIELD_MAP key.

    Templates decorate a heading with its requiredness — `### **Change Type**
    **\\[REQUIRED\\]**`. That marker is presentation; the field name is what is
    left once it comes off.
    """
    return normalize(BOLD_BRACKET_TOKEN_RE.sub(" ", title or ""))


def is_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("`").strip("*").strip()
    v = MD_LINK_ANY_RE.sub(r"\1", v).strip()
    if not v:
        return True
    return bool(PLACEHOLDER_RE.match(v))


# --- markdown parsing -----------------------------------------------------------


def strip_comments(text: str) -> str:
    """Drop HTML comments — in a template most of the instructions live in them."""
    return HTML_COMMENT_RE.sub("", text or "")


def extract_section(
    description: str, heading: str, stop_at_any_heading: bool = False
) -> Optional[str]:
    """Return the body under the heading whose text CONTAINS `heading`.

    Fuzzy on purpose: the section is `## Significant Change` in one template and
    `## FedRAMP Significant Change Notification (SCN)` in another, and both mean
    the same thing. Ends at the next heading of the same or higher level, at a
    horizontal rule (which is how the change-request template closes the SCN
    block before `### Schedule`), or — with stop_at_any_heading — at any heading.
    """
    lines = (description or "").splitlines()
    needle = normalize(heading)

    start = None
    level = 0
    for i, line in enumerate(lines):
        m = HEADING_RE.match(line.strip())
        if m and needle in normalize(m.group("title")):
            start = i + 1
            level = len(m.group("hashes"))
            break
    if start is None:
        return None

    for j in range(start, len(lines)):
        stripped = lines[j].strip()
        m = HEADING_RE.match(stripped)
        if m and (stop_at_any_heading or len(m.group("hashes")) <= level):
            return "\n".join(lines[start:j])
        if HR_RE.match(stripped):
            return "\n".join(lines[start:j])
    return "\n".join(lines[start:])


def clean_uri_value(value: str) -> str:
    """Unwrap a URI from the Markdown people paste it inside.

    `[CPO](https://…)`, `<https://…>`, and `` `https://…` `` all reach us as the
    raw text of a field. Left alone they fail the absolute-URI check for a reason
    that has nothing to do with the URI.
    """
    v = (value or "").strip()
    m = MD_LINK_RE.match(v)
    if m:
        v = m.group("url").strip()
    v = v.strip("`").strip()
    if v.startswith("<") and v.endswith(">"):
        v = v[1:-1].strip()
    return v.strip()


URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s`<>\"]+")


def extract_uri(body: str) -> Optional[str]:
    """Find the URI in a block, whatever it is wrapped in.

    Deliberately NOT built on strip_annotations: that helper strips parenthesised
    instruction text, and the CPO URI ends in "(1).json", so running it over an
    already-extracted URI silently amputates the "(1)". Ask for the URI directly.
    """
    text = (body or "").strip()
    for span in BACKTICK_SPAN_RE.findall(text):
        if "://" in span:
            return span.strip()
    unwrapped = clean_uri_value(text)
    if "://" in unwrapped and not unwrapped.split("://", 1)[1].startswith(" "):
        if len(unwrapped.split()) == 1:
            return unwrapped
    m = URL_RE.search(text)
    if m:
        return m.group(0).rstrip("`)>\"',.")
    return None


def clean_body(body: str) -> str:
    """Drop checkbox lines, unwrap soft-wrapped prose, collapse blank runs.

    Markdown editors hard-wrap paragraphs at ~80 columns. Those newlines are a
    rendering artifact, not authorial intent, and carrying them into
    `changeDescription` gives FedRAMP a field with line breaks mid-sentence. So
    prose paragraphs get joined into one line, while list items, code fences,
    tables, and quotes keep their structure — `planAndTimeline.summary` is
    explicitly allowed to be Markdown.
    """
    kept = [l for l in body.splitlines() if not CHECKBOX_LINE_RE.match(l)]

    out: List[str] = []
    para: List[str] = []
    in_code = False

    def flush() -> None:
        if para:
            out.append(" ".join(part.strip() for part in para))
            para.clear()

    for line in kept:
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            in_code = not in_code
            out.append(line)
            continue
        if in_code:
            out.append(line)
            continue
        if not stripped:
            flush()
            out.append("")
            continue
        if re.match(r"^\s*([-*+]|\d+[.)])\s+|^\s*>|^\s*\||^#{1,6}\s", line):
            flush()
            out.append(line)
            continue
        para.append(line)
    flush()

    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def parse_list(body: str) -> List[str]:
    """Bullet list, or a single comma-separated line. Both are in the wild."""
    items = [m.group("item").strip() for m in (BULLET_RE.match(l) for l in body.splitlines()) if m]
    if items:
        return [i for i in items if i]
    flat = " ".join(body.split())
    if not flat:
        return []
    return [part.strip() for part in flat.split(",") if part.strip()]


def parse_milestones(body: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """`YYYY-MM-DD | description`, `date — description`, `description (date)`.

    A milestone whose date is still the `YYYY-MM-DD` placeholder keeps its
    description and loses the date — the description is real information and
    dropping the whole row would hide that someone planned the step.
    """
    milestones: List[Dict[str, Any]] = []
    notes: List[str] = []
    undated = 0

    for item in parse_list(body):
        date_match = ISO_DATE_RE.search(item)
        target_date = date_match.group(1) if date_match else None

        text = DATE_TOKEN_RE.sub(" ", item)
        text = text.replace("`", " ").strip()
        text = text.strip("()[]").strip()
        text = re.sub(r"^[\s\-–—:•|]+", "", text)
        text = re.sub(r"[\s\-–—:|]+$", "", text).strip()
        text = " ".join(text.split())

        if not text and not target_date:
            continue
        if is_placeholder(text):
            continue

        entry: Dict[str, Any] = {"milestoneDescription": text or item.strip()}
        if target_date:
            entry["targetDate"] = target_date
        else:
            undated += 1
        milestones.append(entry)

    if undated:
        notes.append(
            f"{undated} milestone(s) have no target date — the YYYY-MM-DD placeholder was left in place"
        )
    return milestones, notes


def ticked_labels(body: str) -> List[str]:
    """Labels of ticked checkboxes, with Markdown links reduced to their text."""
    out: List[str] = []
    for line in (body or "").splitlines():
        m = CHECKBOX_RE.match(line)
        if m and m.group("mark").lower() == "x":
            label = MD_LINK_ANY_RE.sub(r"\1", m.group("label"))
            label = label.replace("*", "").strip()
            label = re.sub(r"^[\s\-–—]+|[\s\-–—]+$", "", label)
            if label:
                out.append(label)
    return out


def strip_annotations(text: str) -> str:
    """Remove a marker line's decoration, leaving only an actual value.

    A marker line is mostly annotation:
        **Certification Package Overview URI** *(`…Uri`)* **[REQUIRED]** `https://…`
        **Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)* (List KSI … one per line.)
    The first carries a real value in backticks; the second carries only
    instructions. Backticked spans win when present, because that is where this
    template puts values; otherwise strip the annotation and see what is left.
    """
    t = SCHEMA_MARKER_RE.sub(" ", text or "")
    spans = BACKTICK_SPAN_RE.findall(t)
    if spans:
        return " ".join(s.strip() for s in spans).strip()
    t = BOLD_BRACKET_TOKEN_RE.sub(" ", t)
    t = PARENTHETICAL_RE.sub(" ", t)
    t = BOLD_LABEL_RE.sub(" ", t)
    t = t.replace("*", " ")
    return " ".join(t.split()).strip()


def parse_schema_markers(section: str) -> Dict[str, str]:
    """Split a section on its `*(`schemaKey`)*` annotations into key -> raw body.

    Everything from a marker to the next marker belongs to that field, including
    the remainder of the marker's own line.
    """
    blocks: Dict[str, List[str]] = {}
    current: Optional[str] = None

    for line in (section or "").splitlines():
        m = SCHEMA_MARKER_RE.search(line)
        key = m.group("key") if m else None
        if key and key in KNOWN_SCHEMA_KEYS:
            current = key
            blocks.setdefault(current, [])
            remainder = strip_annotations(line)
            if remainder:
                blocks[current].append(remainder)
            continue
        if BOLD_ONLY_LINE_RE.match(line):
            # A grouping header like `**Impact Analysis**` closes the field above
            # it. Without this, `N/A` under **Assessor Name** absorbs the header
            # and stops looking like the placeholder it is.
            current = None
            continue
        if current:
            blocks[current].append(line)

    return {k: "\n".join(v).strip() for k, v in blocks.items()}


def parse_section(section: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Split a section into (heading -> body, inline key -> value).

    Sub-headings of any level become blocks. `**Key:** value` lines are pulled out
    wherever they appear — including inside a block — because that is how people
    actually write them (a `**Planned Start:**` under `### Plan and Timeline`).
    """
    blocks: Dict[str, List[str]] = {}
    kvs: Dict[str, str] = {}
    current = ""
    blocks[current] = []

    for raw in (section or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        m = HEADING_RE.match(stripped)
        if m:
            current = normalize_heading(m.group("title"))
            blocks.setdefault(current, [])
            continue

        kv = KV_RE.match(stripped)
        if kv and not SCHEMA_MARKER_RE.search(stripped):
            key = kv.group("key").strip().lower()
            value = kv.group("value").strip()
            if value:
                kvs[key] = value
            # A `**Key:** value` line is metadata, not prose — keep it out of the
            # block body so summaries don't end up with label noise in them.
            continue

        blocks[current].append(line)

    return {k: "\n".join(v).strip() for k, v in blocks.items()}, kvs


def set_nested(target: Dict[str, Any], dotted: str, value: Any) -> None:
    head, _, tail = dotted.partition(".")
    if not tail:
        target[head] = value
        return
    target.setdefault(head, {})
    set_nested(target[head], tail, value)


def coerce_field(
    field: str, body: str, notes: List[str], label: str
) -> Optional[Any]:
    """Turn a raw block into the value the schema wants, or None to omit it."""
    if field == "changeType":
        ticked = [t for t in ticked_labels(body) if normalize(t) in CHANGE_TYPE_CANON]
        if len(ticked) > 1:
            notes.append(f"{label}: more than one change type is ticked ({', '.join(ticked)})")
            return None
        if ticked:
            return CHANGE_TYPE_CANON[normalize(ticked[0])]
        flat = strip_annotations(body) or clean_body(body)
        canon = CHANGE_TYPE_CANON.get(normalize(flat))
        if canon:
            return canon
        # A checkbox pair with nothing ticked is the common case, and quoting 60
        # characters of the explanatory blurb back at the reader helps nobody.
        if any(CHECKBOX_RE.match(l) for l in (body or "").splitlines()):
            notes.append(f"{label}: neither Adaptive nor Transformative is ticked")
        elif is_placeholder(flat) or not flat:
            notes.append(f"{label}: no change type given — add Adaptive or Transformative")
        else:
            notes.append(f"{label}: '{flat[:60]}' is not Adaptive or Transformative")
        return None

    if field in URI_FIELDS:
        value = extract_uri(body)
        if not value or is_placeholder(value):
            return None
        return value

    if field in DATE_FIELDS:
        m = ISO_DATE_RE.search(body or "")
        if not m:
            notes.append(f"{label}: no date filled in (still the YYYY-MM-DD placeholder)")
            return None
        return m.group(1)

    if field == "planAndTimeline.milestones":
        milestones, milestone_notes = parse_milestones(body)
        notes.extend(f"{label}: {n}" for n in milestone_notes)
        return milestones or None

    if field in LIST_FIELDS:
        raw = parse_list(clean_body(body))
        items = [i.strip().strip("`").strip() for i in raw]
        real = [i for i in items if i and not is_placeholder(i)]
        dropped = [i for i in items if i and is_placeholder(i)]
        if dropped:
            notes.append(
                f"{label}: {len(dropped)} placeholder entr{'y' if len(dropped) == 1 else 'ies'} "
                f"left unfilled ({', '.join(dropped[:4])})"
            )
        return real or None

    text = clean_body(body)
    text = TEXT_FIELDS_WITH_LABEL_PREFIX.sub("", text).strip()
    if not text or is_placeholder(text):
        return None
    return text


def build_scn(
    section: str,
    full_description: str,
    default_cert_uri: str,
    fallback_description: str,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """Assemble an SCN object from one MR.

    Returns (scn, provenance_extras, parse_notes). Parse notes are human-readable
    remarks about what the MR did not supply — they are evidence in their own
    right and are surfaced in the payload.
    """
    scn: Dict[str, Any] = {}
    extras: Dict[str, Any] = {}
    notes: List[str] = []

    # (a) Schema-key annotations — authoritative when the template carries them.
    marker_blocks = parse_schema_markers(section)
    for field, body in marker_blocks.items():
        if field == "planAndTimeline":
            continue  # a grouping label, not a leaf field
        value = coerce_field(field, body, notes, field)
        if value is not None:
            set_nested(scn, field, value)

    blocks, kvs = parse_section(section)

    # (b) `**Key:** value` inline pairs, for templates without annotations.
    for key, value in kvs.items():
        field = KV_FIELD_MAP.get(key)
        if not field:
            continue
        if field.startswith("_"):
            if not is_placeholder(value):
                set_nested(extras, field.lstrip("_"), value)
            continue
        if _already_set(scn, field):
            continue
        coerced = coerce_field(field, value, notes, key)
        if coerced is not None:
            set_nested(scn, field, coerced)

    # (c) Heading names, for templates without annotations.
    for heading, body in blocks.items():
        field = HEADING_FIELD_MAP.get(heading)
        if not field or _already_set(scn, field):
            continue
        value = coerce_field(field, body, notes, heading)
        if value is not None:
            set_nested(scn, field, value)

    # Approver: SCN-CSO-INF requires a name and title; the schema has no field.
    for key in ("approver", "approver name"):
        if key in kvs and not is_placeholder(kvs[key]):
            extras.setdefault("approver", {})["name"] = kvs[key]
    if "approver title" in kvs and not is_placeholder(kvs["approver title"]):
        extras.setdefault("approver", {})["title"] = kvs["approver title"]

    # Fields the change-request template holds OUTSIDE the SCN section. Looking
    # there is not a liberty: the content is on the same merge request, written
    # for this change, and the alternative is a required field falling back to a
    # branch name. Every borrow is recorded.
    if not scn.get("changeDescription"):
        borrowed, source = _borrow_by_marker(full_description, "changeDescription")
        if not borrowed:
            borrowed, source = _borrow(full_description, ["Requested Changes", "Summary", "Description"])
        if borrowed:
            scn["changeDescription"] = borrowed
            notes.append(f"changeDescription taken from the MR's '{source}' section")
        elif fallback_description:
            scn["changeDescription"] = fallback_description
            notes.append("changeDescription fell back to the MR title")
        else:
            notes.append("changeDescription missing and no MR title to fall back on")

    if not scn.get("impactAnalysis"):
        borrowed, source = _borrow_by_marker(full_description, "impactAnalysis")
        if not borrowed:
            borrowed, source = _borrow(
                full_description,
                ["Impact and Security Analysis", "Impact Analysis", "Security Impact Analysis"],
            )
        if borrowed:
            scn["impactAnalysis"] = borrowed
            notes.append(f"impactAnalysis taken from the MR's '{source}' section")

    if not scn.get("certificationPackageOverviewUri") and default_cert_uri:
        scn["certificationPackageOverviewUri"] = default_cert_uri

    if "changeType" not in scn and not any(
        "change type" in n.lower() or "changetype" in n.lower() for n in notes
    ):
        notes.append("changeType missing — tick Adaptive or Transformative")

    plan = scn.get("planAndTimeline")
    if isinstance(plan, dict) and "summary" not in plan:
        # planAndTimeline.summary is required *if* the object exists. Dates or
        # milestones with no summary would fail validation on a technicality.
        notes.append(
            "planAndTimeline has dates or milestones but no summary — "
            "the summary is required whenever the block is present"
        )

    return scn, extras, notes


def _already_set(scn: Dict[str, Any], dotted: str) -> bool:
    node: Any = scn
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return node not in (None, "", [], {})


def _borrow_by_marker(description: str, field: str) -> Tuple[Optional[str], Optional[str]]:
    """Body of a heading OUTSIDE the SCN section annotated with this schema key.

    `changeDescription` and `impactAnalysis` are FedRAMP fields the change-request
    template has no slot for inside the SCN block — the content lives further up,
    under `## Requested Changes` and `### Impact and Security Analysis`. Annotating
    those headings, e.g.

        ## Requested Changes *(`changeDescription`)*

    makes the mapping explicit and portable: a team can point the field at any
    heading they like without anyone editing the alias list in this file.
    """
    lines = (description or "").splitlines()
    for i, line in enumerate(lines):
        h = HEADING_RE.match(line.strip())
        if not h:
            continue
        m = SCHEMA_MARKER_RE.search(h.group("title"))
        if not m or m.group("key") != field:
            continue
        level = len(h.group("hashes"))
        body: List[str] = []
        for nxt in lines[i + 1:]:
            if HEADING_RE.match(nxt.strip()) or HR_RE.match(nxt.strip()):
                break
            body.append(nxt)
        text = clean_body("\n".join(body))
        if text and not is_placeholder(text):
            title = SCHEMA_MARKER_RE.sub("", h.group("title")).strip()
            return text, title
        # An annotated-but-empty heading is a deliberate choice, not an oversight:
        # fall through to the name-based aliases rather than reporting nothing.
        _ = level
    return None, None


def _borrow(description: str, headings: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """First non-empty, non-placeholder section body among `headings`."""
    for heading in headings:
        body = extract_section(description, heading, stop_at_any_heading=True)
        if body is None:
            continue
        text = clean_body(body)
        if text and not is_placeholder(text):
            return text, heading
    return None, None


def parse_change_request_form(description: str) -> Dict[str, Any]:
    """Provenance from the change-request form wrapped around the SCN section.

    None of this belongs in the FedRAMP object, and all of it matters to whoever
    reads the evidence: an emergency change follows SCN-CSO-EMG rather than the
    normal path, and the completion checkbox is what starts the "within N business
    days of finishing" clock.
    """
    form: Dict[str, Any] = {
        "emergency_change": bool(EMERGENCY_RE.search(description or "")),
        "routine_recurring_declared": bool(ROUTINE_RECURRING_RE.search(description or "")),
    }
    scope = extract_section(description, "Scope", stop_at_any_heading=True)
    if scope:
        form["scope"] = ticked_labels(scope)
    impact = extract_section(description, "Impact", stop_at_any_heading=True)
    if impact:
        classes = [l for l in ticked_labels(impact) if re.match(r"^C\d\b", l)]
        if classes:
            form["impact_class"] = classes
    results = extract_section(description, "Results", stop_at_any_heading=True)
    if results:
        form["result"] = ticked_labels(results)
    return form


# --- validation -----------------------------------------------------------------


def assess_completeness(scn: Dict[str, Any], extras: Dict[str, Any]) -> Dict[str, Any]:
    """Check an SCN against SCN-CSO-INF, not just against the JSON schema.

    Returns {complete, missing:[{field, requirement}]}. Every field here is
    OPTIONAL as far as the schema is concerned, which is exactly why this exists:
    the schema cannot tell an empty notification from a complete one, and the
    empty one is the failure that actually costs you at review time.
    """
    missing: List[Dict[str, str]] = []
    for dotted, requirement in SCN_CSO_INF_REQUIREMENTS:
        source = extras if dotted.startswith("_") else scn
        node: Any = source
        for part in dotted.lstrip("_").split("."):
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if node in (None, "", [], {}):
            missing.append({"field": dotted.lstrip("_"), "requirement": requirement})
    return {"complete": not missing, "missing": missing}


def load_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_scn(validator: Draft202012Validator, scn: Dict[str, Any]) -> List[str]:
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(scn), key=lambda e: list(e.absolute_path))
    ]
    # jsonschema only checks `format: uri` when rfc3987 is installed, which it
    # is not here. Check it ourselves rather than let a bare string through.
    uri = scn.get("certificationPackageOverviewUri")
    if isinstance(uri, str):
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            errors.append("certificationPackageOverviewUri: not an absolute URI")
    return errors


# --- GitLab collection ----------------------------------------------------------


class GitLabClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.api = f"{base_url.rstrip('/')}/api/v4"
        self.headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
        self.failures: List[Dict[str, Any]] = []

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        url = f"{self.api}{path}"
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            self.failures.append({"path": path, "type": type(e).__name__, "message": str(e)})
            return None
        if resp.status_code != 200:
            self.failures.append(
                {"path": path, "type": "HTTPError", "message": f"{resp.status_code} {resp.text[:200]}"}
            )
            return None
        return resp

    def list_merge_requests(
        self, project: str, state: str, days_back: int, max_results: int, labels: str
    ) -> List[Dict[str, Any]]:
        encoded = quote(project, safe="")
        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat().replace("+00:00", "Z")
        params: Dict[str, Any] = {
            "state": state,
            "order_by": "updated_at",
            "sort": "desc",
            "per_page": 100,
            "page": 1,
            "updated_after": since,
        }
        if labels:
            params["labels"] = labels

        out: List[Dict[str, Any]] = []
        while len(out) < max_results:
            resp = self.get(f"/projects/{encoded}/merge_requests", params)
            if resp is None:
                break
            page = resp.json()
            out.extend(page)
            if len(page) < 100 or len(out) >= max_results:
                break
            next_page = resp.headers.get("x-next-page") or resp.headers.get("X-Next-Page")
            if not next_page:
                break
            params["page"] = int(next_page)
        return out[:max_results]

    def approvals(self, project: str, iid: int) -> Dict[str, Any]:
        encoded = quote(project, safe="")
        resp = self.get(f"/projects/{encoded}/merge_requests/{iid}/approvals")
        return resp.json() if resp is not None else {}


def is_marked(description: str, mr: Dict[str, Any], marker_label: str) -> Tuple[bool, Optional[str]]:
    """Marked = ticked checkbox, or the configured GitLab label is present."""
    if marker_label:
        labels = [l.lower() for l in (mr.get("labels") or [])]
        if marker_label.lower() in labels:
            return True, "label"
    if MARKER_RE.search(description or ""):
        return True, "checkbox"
    return False, None


def collect(
    client: GitLabClient,
    project: str,
    state: str,
    days_back: int,
    max_results: int,
    marker_label: str,
    section_heading: str,
    cert_uri: str,
    validator: Draft202012Validator,
) -> Dict[str, Any]:
    mrs = client.list_merge_requests(project, state, days_back, max_results, marker_label)

    notifications: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for mr in mrs:
        description = strip_comments(mr.get("description") or "")
        marked, via = is_marked(description, mr, marker_label)
        if not marked:
            if UNTICKED_MARKER_RE.search(description):
                routine = bool(ROUTINE_RECURRING_RE.search(description))
                skipped.append(
                    {
                        "iid": mr.get("iid"),
                        "title": mr.get("title"),
                        "web_url": mr.get("web_url"),
                        "routine_recurring_declared": routine,
                        "reason": (
                            "author declared the change Routine Recurring (SCN-RTR) — no notification required"
                            if routine
                            else "significant-change checkbox present but not ticked, and no routine-recurring declaration"
                        ),
                    }
                )
            continue

        section = extract_section(description, section_heading)
        iid = mr.get("iid")
        approvals = client.approvals(project, iid) if iid is not None else {}
        form = parse_change_request_form(description)

        provenance = {
            # Stable across runs: a weekly run with a 30-day window re-emits the
            # same MR four times, and whatever submits these needs to recognize
            # them as one notification rather than four.
            "notification_id": f"SCN-{sanitize_for_filename(project)}-{iid}",
            "iid": iid,
            "title": mr.get("title"),
            "state": mr.get("state"),
            "author": (mr.get("author") or {}).get("name"),
            "author_username": (mr.get("author") or {}).get("username"),
            "created_at": mr.get("created_at"),
            "merged_at": mr.get("merged_at"),
            "merged_by": (mr.get("merged_by") or {}).get("name") if mr.get("merged_by") else None,
            "merge_commit_sha": mr.get("merge_commit_sha") or mr.get("sha"),
            "source_branch": mr.get("source_branch"),
            "target_branch": mr.get("target_branch"),
            "web_url": mr.get("web_url"),
            "labels": mr.get("labels") or [],
            "marked_via": via,
            "approvers": [
                (a.get("user") or {}).get("name") for a in (approvals.get("approved_by") or [])
            ],
            "approvals_required": approvals.get("approvals_required", 0),
            "change_request_form": form,
        }

        if section is None:
            notifications.append(
                {
                    "merge_request": provenance,
                    "scn": None,
                    "validation": {
                        "valid": False,
                        "errors": [f"no '{section_heading}' section found in the MR description"],
                    },
                    "completeness": {
                        "complete": False,
                        "missing": [
                            {"field": f, "requirement": r} for f, r in SCN_CSO_INF_REQUIREMENTS
                        ],
                    },
                    "parse_notes": [
                        "MR is marked as a significant change but has no "
                        f"'{section_heading}' section to read"
                    ],
                }
            )
            continue

        scn, extras, notes = build_scn(section, description, cert_uri, mr.get("title") or "")
        errors = validate_scn(validator, scn)
        completeness = assess_completeness(scn, extras)
        if form.get("emergency_change"):
            notes.append("flagged as an Emergency Change — SCN-CSO-EMG applies, not the standard path")

        entry: Dict[str, Any] = {
            "merge_request": provenance,
            "scn": scn,
            "validation": {"valid": not errors, "errors": errors},
            "completeness": completeness,
            "parse_notes": notes,
        }
        if extras.get("approver"):
            entry["approver"] = extras["approver"]
        notifications.append(entry)

    valid_count = sum(1 for n in notifications if n["validation"]["valid"])
    by_type: Dict[str, int] = {}
    for n in notifications:
        change_type = (n.get("scn") or {}).get("changeType") or "unspecified"
        by_type[change_type] = by_type.get(change_type, 0) + 1

    return {
        "merge_requests_scanned": len(mrs),
        "notifications": notifications,
        "skipped_unticked": skipped,
        "summary": {
            "flagged_count": len(notifications),
            "schema_valid_count": valid_count,
            "schema_invalid_count": len(notifications) - valid_count,
            "by_change_type": by_type,
            "unticked_marker_count": len(skipped),
            "routine_recurring_count": sum(1 for s in skipped if s.get("routine_recurring_declared")),
            "emergency_change_count": sum(
                1
                for n in notifications
                if n["merge_request"]["change_request_form"].get("emergency_change")
            ),
            "notifications_with_parse_notes": sum(1 for n in notifications if n["parse_notes"]),
            "scn_cso_inf_complete_count": sum(1 for n in notifications if n["completeness"]["complete"]),
            "scn_cso_inf_incomplete_count": sum(1 for n in notifications if not n["completeness"]["complete"]),
        },
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    config_warnings: List[str] = []
    try:
        gitlab_url = get_env("GITLAB_URL")
        api_token = get_env("GITLAB_API_TOKEN")
        project_id = get_env("GITLAB_PROJECT_ID")
        # One workspace publishes one Certification Package Overview, and the
        # paramify VER fetchers already read it from PARAMIFY_CERT_PACKAGE_URI
        # (see fetchers/_categories/paramify.yaml). Accept that as the shared
        # source so a single manifest line drives every artifact that carries
        # certificationPackageOverviewUri. FEDRAMP_CERT_PACKAGE_URI still wins
        # when set, for a run deliberately targeting a different offering.
        fedramp_uri = clean_uri_value(os.environ.get("FEDRAMP_CERT_PACKAGE_URI", "").strip())
        paramify_uri = clean_uri_value(os.environ.get("PARAMIFY_CERT_PACKAGE_URI", "").strip())

        cert_uri = fedramp_uri or paramify_uri
        cert_uri_source = "FEDRAMP_CERT_PACKAGE_URI" if fedramp_uri else "PARAMIFY_CERT_PACKAGE_URI"
        if not cert_uri:
            raise RuntimeError(
                "Missing required env var: set FEDRAMP_CERT_PACKAGE_URI, or "
                "PARAMIFY_CERT_PACKAGE_URI (platforms.paramify.config.cert_package_uri) "
                "to share one Certification Package Overview URI across every fetcher"
            )

        # Both set and disagreeing is ambiguous, and the quiet resolution is the
        # dangerous one: this URI goes into every notification FedRAMP keeps, so
        # silently picking the wrong document produces permanently wrong records.
        # It is NOT fatal — a run targeting a different service offering sets
        # them differently on purpose — but it is never something to swallow.
        # The usual cause is a stale FEDRAMP_CERT_PACKAGE_URI in a developer .env
        # overriding the manifest, since load_dotenv reads .env directly and
        # bypasses the environment the runner controls.
        if fedramp_uri and paramify_uri and fedramp_uri != paramify_uri:
            config_warnings.append(
                "Two different Certification Package Overview URIs are configured. "
                f"Using FEDRAMP_CERT_PACKAGE_URI ({fedramp_uri}); "
                f"PARAMIFY_CERT_PACKAGE_URI says ({paramify_uri}). "
                "Every notification in this run cites the first. If that is not "
                "deliberate, the usual cause is a stale FEDRAMP_CERT_PACKAGE_URI "
                "in a .env overriding the manifest."
            )
    except RuntimeError as e:
        report_failure(str(e), "bad_config")
        return 1

    state = os.environ.get("GITLAB_SCN_STATE", "merged")
    days_back = int(os.environ.get("GITLAB_SCN_DAYS_BACK", "30"))
    max_results = int(os.environ.get("GITLAB_SCN_MAX_RESULTS", "100"))
    marker_label = os.environ.get("GITLAB_SCN_MARKER_LABEL", "").strip()
    section_heading = os.environ.get("GITLAB_SCN_SECTION_HEADING", "Significant Change").strip()
    strict = os.environ.get("GITLAB_SCN_STRICT", "true").strip().lower() not in ("false", "0", "no")
    require_complete = os.environ.get(
        "GITLAB_SCN_REQUIRE_COMPLETE", "true"
    ).strip().lower() not in ("false", "0", "no")

    validator = load_validator()
    client = GitLabClient(gitlab_url, api_token)
    result = collect(
        client, project_id, state, days_back, max_results,
        marker_label, section_heading, cert_uri, validator,
    )

    evidence = {
        "metadata": {
            "project_id": project_id,
            "project_name": project_id.split("/")[-1] if "/" in project_id else project_id,
            "project_group": project_id.split("/")[0] if "/" in project_id else "unknown",
            "gitlab_url": gitlab_url,
            "fedramp_schema_id": SCHEMA_ID,
            "fedramp_schema_version": json.loads(SCHEMA_PATH.read_text()).get("$schemaVersion"),
            "certification_package_overview_uri": cert_uri,
            "certification_package_overview_uri_source": cert_uri_source,
            "section_heading": section_heading,
            "marker_label": marker_label or None,
            "state_filter": state,
            "days_back": days_back,
            "strict": strict,
            "require_scn_cso_inf_complete": require_complete,
            "scan_timestamp": current_timestamp(),
        },
        "status": "success" if not client.failures else "error",
        "config_warnings": config_warnings,
        **result,
        "api_failures": client.failures,
        "retrieved_at": current_timestamp(),
    }

    output_path = output_dir / f"gitlab_significant_change_notifications_{sanitize_for_filename(project_id)}.json"
    output_path.write_text(json.dumps(evidence, indent=2, default=str))
    for w in config_warnings:
        logger.warning("%s", w)
    logger.info("Evidence saved to %s", output_path)

    # Last line on stderr wins: the runner reads its tail into the envelope's
    # metadata.error. Everything below must log AFTER the "Evidence saved" line.
    if client.failures:
        reason = f"{len(client.failures)} GitLab API failures during collection"
        report_failure(reason, "partial_failure")
        return 1

    invalid = result["summary"]["schema_invalid_count"]
    if invalid and strict:
        iids = [n["merge_request"]["iid"] for n in result["notifications"] if not n["validation"]["valid"]]
        reason = (
            f"{invalid} merge request(s) marked as significant changes did not produce a "
            f"schema-valid FedRAMP SCN: MR {', '.join('!' + str(i) for i in iids)}"
        )
        report_failure(reason, "partial_failure")
        return 1

    # Schema-valid is a low bar: FedRAMP's schema requires three properties, while
    # SCN-CSO-INF asks for a dozen. A notification can validate cleanly and still
    # name no impacted controls, no dates, and no approver — which is the version
    # a reviewer rejects. Failing here is the difference between "well-formed" and
    # "worth sending".
    incomplete = [n for n in result["notifications"] if not n["completeness"]["complete"]]
    if incomplete and require_complete:
        detail = "; ".join(
            "MR !{}: missing {}".format(
                n["merge_request"]["iid"],
                ", ".join(m["field"] for m in n["completeness"]["missing"]),
            )
            for n in incomplete
        )
        reason = (
            f"{len(incomplete)} schema-valid notification(s) are incomplete under "
            f"SCN-CSO-INF — {detail}"
        )
        report_failure(reason, "partial_failure")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
