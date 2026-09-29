# Splunk

Seven fetchers read a Splunk Enterprise deployment's management REST API
(port 8089) with a bearer token. Every fetcher fans out per deployment: each
target is one search head or standalone instance with its own URL and token.

| Fetcher | Evidence set | KSIs | Collects |
|---|---|---|---|
| `splunk_log_source_freshness` | `EVD-SPLUNK-LOG-SOURCE-FRESHNESS` | MLA-OSM, MLA-LET | every host that has sent data and every forwarder connection, each judged `silent` against the window |
| `splunk_data_inputs` | `EVD-SPLUNK-DATA-INPUTS` | MLA-LET | every configured input, and every (host, index, sourcetype) stream actually received |
| `splunk_index_activity` | `EVD-SPLUNK-INDEX-ACTIVITY` | MLA-OSM | every index: whether it holds data, when it last received data, `stale` |
| `splunk_index_retention` | `EVD-SPLUNK-INDEX-RETENTION` | MLA-OSM | every index: retention days, archive or delete on freeze, data integrity control |
| `splunk_alert_rules` | `EVD-SPLUNK-ALERT-RULES` | MLA-OSM, MLA-RVL | every scheduled search Splunk classes as an alert, its actions and recipients, and how often it ran and fired |
| `splunk_alert_delivery` | `EVD-SPLUNK-ALERT-DELIVERY` | MLA-RVL | email action settings, and each triggered alert action's delivery attempts and outcomes |
| `splunk_role_index_access` | `EVD-SPLUNK-ROLE-INDEX-ACCESS` | MLA-ALA | effective searchable indexes per role and user, delete rights, dormant accounts |

Each writes `$EVIDENCE_DIR/<fetcher>_<target name>.json`.

---

## Targets and credentials

| Target field | Env var | Required | Description |
|---|---|---|---|
| `name` | `SPLUNK_TARGET_NAME` | Yes | Label for the deployment; used in the evidence filename. |
| `base_url` | `SPLUNK_BASE_URL` | Yes | Management URL, e.g. `https://splunk.example.com:8089`. Port 8089, not the 8000 web UI. |
| `verify_ssl` | `SPLUNK_VERIFY_SSL` | No | Default `true`. Set `false` only for a self-signed test instance. |
| `ca_bundle` | `SPLUNK_CA_BUNDLE` | No | CA bundle that signed the certificate, for a private CA. Overrides `verify_ssl`. |

| Secret | Env var | Description |
|---|---|---|
| `token` (per target) | `SPLUNK_TOKEN` | Splunk authentication token for the collection user. |

Every evidence file records `metadata.tls_verified`, so a reader can see
whether the collection authenticated the server.

| Config key | Env var | Default | Used by |
|---|---|---|---|
| `max_silence_minutes` (category) | `SPLUNK_MAX_SILENCE_MINUTES` | 60 | freshness, data inputs, index activity |
| `forwarder_lookback_days` | `SPLUNK_FORWARDER_LOOKBACK_DAYS` | 30 | log source freshness |
| `alert_lookback_days` | `SPLUNK_ALERT_LOOKBACK_DAYS` | 30 | alert rules |
| `delivery_lookback_days` | `SPLUNK_DELIVERY_LOOKBACK_DAYS` | 30 | alert delivery |
| `dormant_days` | `SPLUNK_DORMANT_DAYS` | 90 | role index access |

The lookbacks read `_internal`, whose default retention is 30 days; a longer
window covers only what is still there (`alert_delivery` records the oldest
event in `metadata.internal_earliest_event`).

## Creating a token

Token authentication is **off by default** in Splunk Enterprise.

1. Sign in to Splunk Web as an admin.
2. **Settings → Tokens**, and enable token authentication (Token Settings).
3. Create the collection user and give it the role below.
4. **Settings → Tokens → New Token**, for that user, with an expiry.
5. Store the token in your secrets manager and reference it as `SPLUNK_TOKEN`.

## Required permissions

Each fetcher checks the token's capabilities
(`/services/authentication/current-context`) before collecting and fails,
naming what is missing, rather than publish a partial list.

| Fetcher | Capabilities | Index access |
|---|---|---|
| `splunk_log_source_freshness` | `search` | every enabled index, `*` and `_*` |
| `splunk_data_inputs` | `search`, `list_inputs`, `rest_properties_get` | every enabled index, `*` and `_*` |
| `splunk_index_activity` | `search`, `rest_properties_get` | every enabled index, `*` and `_*` |
| `splunk_index_retention` | `search`, `rest_properties_get` | none beyond `search` |
| `splunk_alert_rules` | `search`, `admin_all_objects` | `_audit`, `_internal` |
| `splunk_alert_delivery` | `search`, `rest_properties_get` | `_internal` |
| `splunk_role_index_access` | `search`, `list_all_roles`, `list_all_users`, `rest_properties_get` | collection user granted `*` and `_*`, nothing disallowed |

**Stock `admin` is not enough.** On Splunk Enterprise 10.4.2, `admin`'s 194
effective capabilities include `admin_all_objects`, `rest_properties_get`,
`list_inputs` and `search`, but not `list_all_users` or `list_all_roles`, so
`splunk_role_index_access` refuses an admin token. Give the collection user a
custom role that adds both. For example, in `authorize.conf`:

```ini
[role_paramify_evidence]
importRoles = user
srchIndexesAllowed = *;_*
admin_all_objects = enabled
list_all_roles = enabled
list_all_users = enabled
list_inputs = enabled
rest_properties_get = enabled
```

`admin_all_objects` is the only way to see saved searches whose ACL grants
read to admin only (every Monitoring Console alert on a stock install), and
Splunk reports the filtered count as the total. It is a broad grant; the
token's expiry and the user's other roles are yours to limit.

Unverified: whether a token without `list_all_users` sees only its own user.
A stock `admin` token, which lacks it, listed both users on the 10.4.2
instance. The fetcher requires the capability either way.

## Completeness

Splunk returns partial data without an error in several ways. The shared
client (`_shared/splunk_client.py`) checks each one and fails the collection:

- **`count` defaults to 30.** Every collection is read with `count=0` and
  must match `paging.total`.
- **Knowledge objects are namespaced.** `/services/saved/searches` returns
  only the caller's app context; the fetchers read `/servicesNS/-/-/`.
- **`data/indexes` omits metric indexes** unless `datatype=all`. The index
  list must also equal the `indexes.conf` stanzas and hold every index the
  search peers can search.
- **A denied search is empty results plus a WARN.** Any WARN or ERROR in a
  search response fails that search.
- **Counts are cross-checked** against an independent search (`tstats
  dc(host)`, `dc(sourcetype)`) and against Splunk's own evaluation of the
  alert filter and of role inheritance.
- **Values mix renderings.** Under `output_mode=json` some fields are native
  booleans and integers and others are strings (`currentDBSizeMB` arrives as
  `"0"`, which is truthy in Python); `as_bool` and `as_int` decode both.

Transient failures (429, 5xx, a connection that did not open) are retried up
to four times with backoff. A field whose call failed is `null`, never `0` or
`false`, and the run exits non-zero with `metadata.partial_failure: true`.

## Wiring into a manifest

```bash
paramify manifest add splunk_role_index_access
paramify manifest add-target splunk_role_index_access \
  name=prod base_url=https://splunk.example.com:8089 \
  --secret token=SPLUNK_TOKEN
```

Repeat for each fetcher, or start from `examples/splunk_run.yaml`, which
runs all seven against one target.

## Known limitations

- Proven on Splunk Enterprise 10.4.x standalone only. Splunk Cloud's REST API
  reaches only the search tier and is untested, as are distributed
  deployments.
- `splunk_index_activity` fails on a distributed deployment unless the search
  head defines the indexers' indexes.
- `splunk_data_inputs` sees only the queried instance's `inputs.conf`; inputs
  on forwarders appear only as the streams in `received[]`.
- `splunk_alert_delivery` parses `_internal` log lines (`sendemail`,
  `sendmodalert`), whose wording can change between Splunk versions.
- Splunk records nothing after an alert is delivered, and no access review, so
  none of this evidence shows an alert was read or a grant was reviewed.
