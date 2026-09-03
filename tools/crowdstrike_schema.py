#!/usr/bin/env python3
"""
Extract CrowdStrike's API response schema, and validate records against it.

Where the schema comes from
---------------------------
CrowdStrike's OpenAPI specification is not publicly downloadable — the asset
host returns 403 without a console session. But **gofalcon**, CrowdStrike's
official Go SDK, is generated *from that specification* and is public. Its
model structs therefore carry the spec's content:

    // The name of the platform
    // Required: true
    // Enum: [Windows Mac Linux]
    PlatformName *string `json:"platform_name"`

That is a field name, a type, a required flag and an enum — everything needed
to check a record structurally rather than by eye.

Why bother
----------
Two of the five fetchers (prevention policies, Zero Trust Assessment) have no
publicly recorded responses anywhere, so they cannot be tested against real
data. They can still be tested against the vendor's *schema*: required fields
present, types right, enum values legal, nested objects well-formed. That is
weaker than real data and stronger than a hand-written fixture, which only ever
proves the fixture agrees with the fetcher that was written alongside it.

Usage
-----
    python tools/crowdstrike_schema.py --refresh   # download, write snapshot
    python tools/crowdstrike_schema.py --validate  # check the mock's fixtures

The snapshot is committed so tests run offline. Refresh it when CrowdStrike
ships API changes and review the diff.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = Path(__file__).resolve().parent / "crowdstrike_models.json"

TREE_URL = "https://api.github.com/repos/CrowdStrike/gofalcon/git/trees/main?recursive=1"
GOFALCON_RAW = "https://raw.githubusercontent.com/CrowdStrike/gofalcon/main"
RAW_BASE = f"{GOFALCON_RAW}/falcon/models"
CLIENT_BASE = f"{GOFALCON_RAW}/falcon/client"

# gofalcon client packages holding the operations these fetchers call. Each
# operation declares its Method and PathPattern, so a wrong URL or verb in a
# fetcher is catchable offline — otherwise it surfaces only as a 404 against a
# live tenant, which is exactly the feedback we do not have.
CLIENT_PACKAGES = [
    "hosts",
    "spotlight_vulnerabilities",
    "alerts",
    "prevention_policies",
    "zero_trust_assessment",
    "filevantage",
    "firewall_policies",
    "firewall_management",
]

# The response model each fetcher's records conform to. Nested models are
# followed automatically, so only the top-level record type is named here.
ROOT_MODELS: Dict[str, str] = {
    "hosts": "DeviceapiDeviceSwagger",
    "spotlight_vulnerabilities": "DomainAPIVulnerabilityV2",
    "detections": "DetectsAlert",
    "prevention_policies": "PreventionPolicyV1",
    "zero_trust_assessment": "CommonCIDAuditResult",
    # The Zero Trust fetcher reads two shapes, not one: the CID audit above and
    # the per-host scores below. Only the audit was listed here, so the host
    # summary went unchecked — the same blind spot that let the audit summary
    # ship reading a record shape that did not exist.
    "zero_trust_assessment_hosts": "DomainZeroTrustSimpleAssessment",
    "filevantage": "ChangesChange",
    # The firewall fetcher reads four shapes across two API families: the policy
    # itself, the container that says whether it is enforced, the rule groups
    # and the rules. Listing only the policy would leave the enforcement fields
    # — the ones the evidence actually turns on — unchecked.
    "firewall_policies": "FirewallPolicyV1",
    "firewall_policy_containers": "FwmgrFirewallPolicyContainerV1",
    "firewall_rule_groups": "FwmgrAPIRuleGroupV1",
    "firewall_rules": "FwmgrFirewallRuleV1",
}

# Response-envelope and pagination models. These are not reachable from the
# record roots above — a record knows nothing about the body wrapping it — but
# they are what the shared client's three paginators read, and a wrong field
# name there ends the loop after page one instead of raising. Collected so that
# behaviour can be pinned too.
ENVELOPE_MODELS = [
    "MsaMetaInfo",                    # meta for most endpoints
    "MsaPaging",                      # integer offset  (alerts queries)
    "DeviceapiMetaInfo",              # meta for devices-scroll
    "DeviceapiDevicePagingV2",        # opaque string offset token
    "DomainAPIQueryPagingV1",         # `after` cursor  (spotlight combined)
    # Zero Trust hands the cursor back as `next`, not `after`. Pinned here
    # because reading only `after` capped that collection at one page.
    "DomainSearchAfterPaging",
    "DetectsapiAlertQueryResponse",   # a full {errors, meta, resources} body
    "MsaAPIError",                    # the errors[] entries
    # Request bodies. The alerts entity lookup takes `composite_ids`, not `ids`,
    # and the wrong key returns an empty result rather than an error.
    "DetectsapiPostEntitiesAlertsV2Request",
]

# Go scalar types mapped to the JSON types they serialise as.
GO_SCALARS: Dict[str, Tuple[type, ...]] = {
    "string": (str,),
    "bool": (bool,),
    "int32": (int,), "int64": (int,), "int": (int,),
    "float32": (float, int), "float64": (float, int),
    "strfmt.DateTime": (str,),
    "strfmt.Date": (str,),
    "interface{}": (object,),
    "jsonext.Number": (int, float),
}

FIELD_RE = re.compile(
    r"^\t(?P<goname>[A-Z]\w*)\s+(?P<gotype>[^\s`]+)\s+`json:\"(?P<tag>[^\"]+)\"`",
    re.MULTILINE,
)


def http_get(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "paramify-fetchers"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def model_file_index() -> Dict[str, str]:
    """Map a normalised model name to its file stem.

    gofalcon's file naming is not a clean transform of the type name
    (`CommonCIDAuditResult` is `common_c_id_audit_result`, but
    `DomainAPIVulnerabilityV2` is `domain_api_vulnerability_v2`), so names are
    matched by stripping underscores and casing from both sides instead of
    trying to reproduce the generator's rule.
    """
    tree = json.loads(http_get(TREE_URL))
    index: Dict[str, str] = {}
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if path.startswith("falcon/models/") and path.endswith(".go"):
            stem = path[len("falcon/models/"):-len(".go")]
            index[stem.replace("_", "").lower()] = stem
    return index


def collect_endpoints() -> Dict[str, str]:
    """Map "METHOD /path" -> operation id, for every operation in the packages
    the fetchers use."""
    endpoints: Dict[str, str] = {}
    pattern = re.compile(
        r'ID:\s*"([^"]+)",\s*Method:\s*"([^"]+)",\s*PathPattern:\s*"([^"]+)"'
    )
    for package in CLIENT_PACKAGES:
        try:
            source = http_get(f"{CLIENT_BASE}/{package}/{package}_client.go")
        except Exception as e:  # noqa: BLE001
            print(f"  ! endpoints for {package}: {e}", file=sys.stderr)
            continue
        for op, method, path in pattern.findall(source):
            endpoints[f"{method} {path}"] = op
    return endpoints


def load_endpoints() -> Dict[str, str]:
    return json.loads(SNAPSHOT_PATH.read_text()).get("endpoints", {})


# --- request parameters -------------------------------------------------------
#
# Every operation has a companion `<operation>_parameters.go` holding the query
# parameters go-swagger actually puts on the wire, plus the spec's parameter
# documentation. Three things worth checking come out of it:
#
#   * accepted query parameter names — a misspelled one is usually *ignored*
#     rather than rejected, so `limit` typo'd silently means the default page
#     size, and a wrong filter key silently means no filtering at all;
#   * the documented `limit` range — over the maximum is a 400 on first contact;
#   * for some endpoints, the list of legal FQL filter fields.
#
# The last is the interesting one. FQL filters are typed as a bare string, so I
# had written them off as unverifiable without a tenant. They are not:
# CrowdStrike documents the legal fields in the parameter comment, so the
# fetchers' default filters can be checked against that list offline.

PARAM_QUERY_RE = re.compile(r'SetQueryParam\("([^"]+)"')
PARAM_BODY_RE = re.compile(r"SetBodyParam\(")
# "Available filter fields that supports exact match: aid, cid, cve.id, ..."
FILTER_FIELDS_RE = re.compile(r"Available filter fields[^:]*:\s*([^\n]+)")
LIMIT_RANGE_RE = re.compile(r"\[(\d+)-(\d+)\]")   # "[1-10000]"
LIMIT_MAX_RE = re.compile(r"max:\s*(\d+)")        # "default: 100, max: 5000"


def parameter_file_index() -> Dict[str, str]:
    """Map a normalised operation id to its `*_parameters.go` path."""
    tree = json.loads(http_get(TREE_URL))
    index: Dict[str, str] = {}
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if not path.endswith("_parameters.go"):
            continue
        if not any(f"/client/{package}/" in path for package in CLIENT_PACKAGES):
            continue
        stem = path.rsplit("/", 1)[-1][: -len("_parameters.go")]
        index[re.sub(r"[^a-z0-9]", "", stem.lower())] = path
    return index


def collect_parameters(endpoints: Dict[str, str]) -> Dict[str, Any]:
    """Map "METHOD /path" -> {query, takes_body, limit_max, filter_fields}."""
    index = parameter_file_index()
    parameters: Dict[str, Any] = {}

    for endpoint, operation in endpoints.items():
        path = index.get(re.sub(r"[^a-z0-9]", "", operation.lower()))
        if not path:
            continue
        try:
            source = http_get(f"{GOFALCON_RAW}/{path}")
        except Exception as e:  # noqa: BLE001
            print(f"  ! parameters for {operation}: {e}", file=sys.stderr)
            continue

        fields = set()
        truncated = False
        for match in FILTER_FIELDS_RE.findall(source):
            # An ellipsis inside the list itself means "and more". Checked per
            # line, not per file — Go's variadic `joinedFacet...` also contains
            # one, and treating that as truncation marks every list incomplete.
            truncated |= "..." in match
            for token in match.split(","):
                token = token.strip().rstrip(".")
                if token and token not in ("N/A", "..."):
                    fields.add(token)

        limit_doc = source[source.find("/* Limit.") :][:400] if "/* Limit." in source else ""
        limit_max: Optional[int] = None
        if range_match := LIMIT_RANGE_RE.search(limit_doc):
            limit_max = int(range_match.group(2))
        elif max_match := LIMIT_MAX_RE.search(limit_doc):
            limit_max = int(max_match.group(1))

        parameters[endpoint] = {
            "operation": operation,
            "query": sorted(set(PARAM_QUERY_RE.findall(source))),
            "takes_body": bool(PARAM_BODY_RE.search(source)),
            "limit_max": limit_max,
            "filter_fields": sorted(fields),
            # Where the list is truncated, an absent field is not proof the
            # field is illegal — so only a complete list can be asserted against.
            "filter_fields_are_complete": bool(fields) and not truncated,
        }
    return parameters


def load_parameters() -> Dict[str, Any]:
    return json.loads(SNAPSHOT_PATH.read_text()).get("parameters", {})


def parse_struct(source: str, type_name: str) -> Optional[Dict[str, Any]]:
    """Parse one Go struct into {field: {type, required, enum, is_list, model}}."""
    match = re.search(rf"^type {re.escape(type_name)} struct \{{\n(.*?)^\}}", source,
                      re.MULTILINE | re.DOTALL)
    if not match:
        return None

    body = match.group(1)
    fields: Dict[str, Any] = {}

    for field in FIELD_RE.finditer(body):
        tag = field.group("tag").split(",")[0]
        if tag in ("", "-"):
            continue

        gotype = field.group("gotype")
        # Everything above this field since the previous one holds its comments.
        preceding = body[:field.start()].rsplit("`json:", 1)[-1]
        comments = preceding[preceding.rfind("\n\n"):] if "\n\n" in preceding else preceding

        enum_match = re.search(r"//\s*Enum:\s*\[([^\]]*)\]", comments)
        is_list = gotype.startswith("[]")
        base = gotype.lstrip("[]").lstrip("*")
        is_map = base.startswith("map[")

        fields[tag] = {
            "go_type": gotype,
            "required": "Required: true" in comments,
            "enum": enum_match.group(1).split() if enum_match else None,
            "is_list": is_list,
            "is_map": is_map,
            "scalar": base if base in GO_SCALARS else None,
            "model": None if (base in GO_SCALARS or is_map) else base,
        }

    return fields


def collect_models(root: str, index: Dict[str, str], seen: Dict[str, Any]) -> None:
    """Fetch a model and everything it references, transitively."""
    if root in seen:
        return
    stem = index.get(root.replace("_", "").lower())
    if not stem:
        seen[root] = {"__missing__": True}
        return

    try:
        source = http_get(f"{RAW_BASE}/{stem}.go")
    except Exception as e:  # noqa: BLE001
        print(f"  ! {root}: {e}", file=sys.stderr)
        seen[root] = {"__missing__": True}
        return

    # go-swagger emits anonymous nested objects (DetectsAlertDevice,
    # ...Items0) inside the parent's file rather than as their own model, so
    # register every struct the file defines, not just the one asked for.
    for name in re.findall(r"^type (\w+) struct \{", source, re.MULTILINE):
        if name in seen and not seen[name].get("__missing__"):
            continue
        parsed = parse_struct(source, name)
        if parsed is not None:
            seen[name] = parsed

    fields = seen.get(root)
    if not fields or fields.get("__missing__"):
        seen[root] = {"__missing__": True}
        return

    for spec in list(fields.values()):
        if spec.get("model"):
            collect_models(spec["model"], index, seen)


def validate(
    record: Any,
    model: str,
    models: Dict[str, Any],
    path: str = "",
    enforce_required: bool = False,
) -> List[str]:
    """Check one record against a model. Returns a list of human-readable problems.

    Extra fields are always fine — the API gains fields over time and a fetcher
    must tolerate that.

    `enforce_required` defaults to **off**, and that is a calibrated choice
    rather than laziness. Validating real recorded responses against this same
    schema produces **626 "required field missing" complaints across 25 real
    alerts, with zero type and zero enum errors**. CrowdStrike's spec marks
    fields required that real responses routinely omit, so treating the flag as
    a hard rule would reject genuine Falcon output. Types and enums, measured
    the same way, are accurate — so those are the checks worth trusting.
    """
    problems: List[str] = []
    fields = models.get(model)
    if not fields or fields.get("__missing__"):
        return [f"{path or '<root>'}: model {model} not in snapshot"]

    if not isinstance(record, dict):
        return [f"{path or '<root>'}: expected an object for {model}, got {type(record).__name__}"]

    for name, spec in fields.items():
        where = f"{path}.{name}" if path else name

        if name not in record or record[name] is None:
            if spec["required"] and enforce_required:
                problems.append(f"{where}: required by {model}, missing")
            continue

        value = record[name]

        if spec["is_list"]:
            if not isinstance(value, list):
                problems.append(f"{where}: expected a list, got {type(value).__name__}")
                continue
            if spec["model"]:
                for i, item in enumerate(value):
                    problems += validate(item, spec["model"], models, f"{where}[{i}]", enforce_required)
            continue

        if spec["is_map"]:
            if not isinstance(value, dict):
                problems.append(f"{where}: expected a map, got {type(value).__name__}")
            continue

        if spec["model"]:
            problems += validate(value, spec["model"], models, where, enforce_required)
            continue

        expected = GO_SCALARS.get(spec["scalar"] or "", ())
        if expected and object not in expected and not isinstance(value, expected):
            problems.append(
                f"{where}: expected {spec['scalar']}, got {type(value).__name__} ({value!r})"
            )

        if spec["enum"] and isinstance(value, str) and value not in spec["enum"]:
            problems.append(f"{where}: {value!r} not in enum {spec['enum']}")

    return problems


def load_models() -> Dict[str, Any]:
    return json.loads(SNAPSHOT_PATH.read_text())["models"]


def main() -> int:
    parser = argparse.ArgumentParser(description="CrowdStrike response schema tooling.")
    parser.add_argument("--refresh", action="store_true", help="download models, write snapshot")
    parser.add_argument("--validate", action="store_true", help="validate the mock's fixtures")
    args = parser.parse_args()

    if args.refresh:
        index = model_file_index()
        models: Dict[str, Any] = {}
        for fetcher, root in ROOT_MODELS.items():
            print(f"{fetcher}: {root}")
            collect_models(root, index, models)
        for extra in ENVELOPE_MODELS:
            print(f"envelope: {extra}")
            collect_models(extra, index, models)
        resolved = sum(1 for m in models.values() if not m.get("__missing__"))
        endpoints = collect_endpoints()
        print(f"\n{len(endpoints)} endpoints across {len(CLIENT_PACKAGES)} packages")
        parameters = collect_parameters(endpoints)
        print(f"{len(parameters)} operations with parameter definitions")
        SNAPSHOT_PATH.write_text(
            json.dumps(
                {"roots": ROOT_MODELS, "models": models, "endpoints": endpoints,
                 "parameters": parameters},
                indent=2, sort_keys=True,
            ) + "\n"
        )
        print(f"\n{resolved}/{len(models)} models resolved -> {SNAPSHOT_PATH}")
        return 0

    if args.validate:
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        import crowdstrike_mock as mock  # noqa: PLC0415

        models = load_models()
        fixtures = {
            "hosts": mock._devices(),
            "spotlight_vulnerabilities": mock._vulnerabilities(),
            "detections": mock._alerts(),
            "prevention_policies": mock._prevention_policies(),
            "zero_trust_assessment": mock._zta_audit(),
        }
        total = 0
        for fetcher, records in fixtures.items():
            problems: List[str] = []
            for i, record in enumerate(records):
                problems += validate(record, ROOT_MODELS[fetcher], models, f"[{i}]")
            total += len(problems)
            status = "ok" if not problems else f"{len(problems)} problem(s)"
            print(f"\n{fetcher}: {len(records)} record(s), {status}")
            for problem in problems[:25]:
                print(f"  - {problem}")
            if len(problems) > 25:
                print(f"  ... and {len(problems) - 25} more")
        return 1 if total else 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
