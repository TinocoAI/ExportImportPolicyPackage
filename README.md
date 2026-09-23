# ExportImportPolicyPackage

Check Point ExportImportPolicyPackage enables you to export a policy package from a Management database to a `.tar.gz` file and import it into any other Management database. Supported from R80.10 and above.

This tool is useful for backups, database migrations, lab testing, and policy replication across Management Servers.

> **Note:** If exporting from a CMA, ensure that no global policy is assigned to that CMA. Global policies are not supported by this tool.

---

## Description

The tool exports a policy package (Access Policy, Threat Policy, or both) from a Management database into a `.tar.gz` archive, which can then be imported into a different Management Server.

### Known Limitations (original)

- Some object types may not be exportable. When this happens, a dummy placeholder object is exported instead and logged. In SmartConsole, search for `export_error` to locate these objects and replace them manually.
- Data Center Objects must be recreated manually on the destination Management Server before importing, using the exact same name as on the source.

---

## Changes and New Features (TinocoAI fork)

This fork introduces several fixes and new features on top of the original CheckPointSW tool, targeting R82 environments.

### Import Prerequisites Report

Before starting the import, the script now scans the export package and produces a **prerequisites report** listing all external dependencies that must exist on the destination Management Server:

- **LDAP Account Units** — detected from Access Role objects that reference AD/LDAP sources. The report shows the Account Unit name, the number of Access Roles that depend on it, and counts of AD groups and direct AD users involved. The import can proceed without the Account Unit, but the affected Access Roles will fail; the API requires the Account Unit to be configured with a valid Login DN and connectivity to the directory before Access Roles referencing it can be created.
- **Gateway / Cluster objects** — Simple Cluster objects (firewalls, HA clusters) cannot be imported via the Management API due to an API limitation (`cluster-xl` parameter not supported). These are listed in the report with their virtual IP and member IPs for reference.

### Cluster Fallback Strategy

When the prerequisites report lists gateway/cluster objects, the script asks how to handle rules that reference them:

1. **Create dummy host placeholders** — a host object is created at the cluster's virtual IP with a `placeholder_cluster_` prefix. Rules import successfully and reference the placeholder. After import, recreate the real cluster object in SmartConsole and replace the placeholder.
2. **Skip entirely** — no object is created. Rules referencing the cluster will fail to import.

### Access Role Import Fix

The original tool failed to import Access Roles that reference AD/LDAP users and groups. This fork adds `clean_access_role_payload()`, which remaps the rich user objects returned by `show-access-role` (containing `accountUnitUid`, `dn`, `display-name`, `tooltiptext`, etc.) into the compact format expected by `add-access-role` (`source` + `selection`). The `remote-access-client` field, which is also rejected by the API, is stripped and defaults to Any.

### Infinite Recursion Fix (access-sections crash)

The original tool had two bugs in `add_object` that caused a `RecursionError` after 977+ recursive calls when importing access-sections:

1. **Operator precedence bug** — the condition `"https-rule" or "threat-exception" in api_type` always evaluated to `True` because a non-empty string is truthy in Python. Fixed to use explicit `in` checks.
2. **No exit condition on position adjustment** — when `Invalid parameter for [position]` was returned by the API and the position decrement did not change, the function would call itself indefinitely. Fixed by detecting a stale decrement and skipping the object instead of looping.

### Object Filter Fix (import_prerequisites.json)

The `import_prerequisites.json` file bundled in the export archive was being picked up by the general object file filter and passed to the sort function, which expected a filename pattern with at least 5 underscore-delimited segments. This caused an `IndexError` at the start of import. Fixed by explicitly excluding `import_prerequisites.json` from the general object file list.

### Dynamic Cluster Detection for Older Archives

For export archives that predate this fork (no `gateway_clusters` key in `import_prerequisites.json`), the script now dynamically scans the simple-cluster JSON files inside the archive and backfills the cluster list at import time.

---

## Requirements

- Python 3.7 or above (from v5.0)
- [Check Point Management API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk)
- Management Server R80.10 or above (tested on R82)

## Instructions

Clone this repository:

```bash
git clone https://github.com/TinocoAI/ExportImportPolicyPackage
```

Or download the ZIP from the [releases page](https://github.com/TinocoAI/ExportImportPolicyPackage/releases).

Download the [Check Point API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk) and set the `PYTHONPATH` to include it:

```bash
export PYTHONPATH=$PYTHONPATH:/path/to/cp_mgmt_api_python_sdk/
```

Run the script:

```bash
python3 import_export_package.py -h
```

### Example — Import

```bash
python3 import_export_package.py \
  -op import \
  -n Policy-PackageName \
  -f /path/to/export.tar.gz \
  -u admin \
  -p <password> \
  -m <management-ip> \
  -ac true \
  --nat true \
  --skip-duplicate-objects true
```

### Example — Export

```bash
python3 import_export_package.py \
  -op export \
  -n PackageName \
  -u admin \
  -p <password> \
  -m <management-ip>
```

Use `-h` for the full list of flags and the current tool version.

---

## Changelog

| Version | Description |
|---------|-------------|
| v6.3.8  | Fix individual AD users in Access Roles: API requires full DN as `selection`, not display-name; groups continue to use display-name |
| v6.3.7  | Fix infinite recursion on `Invalid parameter for [position]` in access-sections; fix operator precedence bug for https-rule/threat-exception |
| v6.3.6  | Cluster fallback strategy (dummy host or skip) for gateway/cluster objects that cannot be imported via API; dynamic cluster detection for older archives |
| v6.3.5  | Exclude `import_prerequisites.json` from general object file list to prevent IndexError on import |
| v6.3.4  | Import prerequisites report: LDAP Account Unit detection and Access Role payload cleanup (`clean_access_role_payload`) |
| v6.3.3  | Original CheckPointSW release (base for this fork) |

---

## Development

Python 3.7+ (from v5.0). Earlier versions (up to v4.2) supported Python 2.7.9.

Original tool by [CheckPointSW](https://github.com/CheckPointSW/ExportImportPolicyPackage).
This fork maintained by [TinocoAI](https://github.com/TinocoAI/ExportImportPolicyPackage).
