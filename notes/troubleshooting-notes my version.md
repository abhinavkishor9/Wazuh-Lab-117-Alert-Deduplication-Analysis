# Troubleshooting Notes

## 1. Windows PowerShell Could Not Find the Wazuh Linux Rules Directory

### Issue

The following command was attempted in Windows PowerShell:

```powershell
Get-ChildItem " /var/ossec/ruleset/rules "
```

PowerShell returned a path error referencing `C:\Windows\System32`.

### Cause

`/var/ossec/ruleset/rules/` is a Linux filesystem path, not a Windows directory. The command also contained unnecessary spaces inside the quoted path.

### Resolution

Run Linux filesystem commands on the Wazuh Manager, rather than in Windows PowerShell.

Check SSH availability from PowerShell:

```powershell
Get-Command ssh
```

If SSH is available, connect using the appropriate Linux username:

```powershell
ssh <your-username>@192.168.203.129
```

After connecting to the manager, execute the Linux commands in the remote terminal.

## 2. Searching the Wazuh Ruleset

### Command

```bash
grep -RInE 'frequency=|timeframe=|ignore=' /var/ossec/ruleset/rules/ /var/ossec/etc/rules/
```

### Result

The search returned multiple rule definitions containing frequency, timeframe, or ignore attributes.

Examples included rules in the Windows base, Windows Security, Sysmon, Windows Defender, and firewall ruleset files.

### Interpretation

The search confirmed that these configuration attributes occur in the ruleset. However, a global search does not establish whether a specific rule uses suppression.

### Next step

Inspect the relevant rule definition and its parent or related rules before drawing conclusions about its behavior.

## 3. Recent Alert Query Returned Zero Documents

### Issue

A query using a 24-hour range and the `data.srcip` existence filter returned:

```json
{
  "hits": {
    "total": {
      "value": 0,
      "relation": "eq"
    },
    "hits": []
  }
}
```

The query completed successfully, with no failed shards.

### Cause

No documents matched the combination of the time range and the requirement that `data.srcip` exist.

This did not establish that the alert index was empty.

### Resolution

First, query the index without the source-IP filter:

```json
GET /wazuh-alerts-*/_search
{
  "size": 5,
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ],
  "query": {
    "match_all": {}
  },
  "_source": [
    "@timestamp",
    "timestamp",
    "rule.id",
    "rule.description",
    "agent.id",
    "agent.name"
  ]
}
```

The query returned recent alerts, confirming that the index pattern contained data.

Use fields that are present in the relevant event type rather than assuming every alert contains a source IP.

## 4. Rule 597 Alerts Appeared Within Milliseconds

### Observation

Multiple Rule `597` records appeared close together around `2026-10-25 05:27:29` local time.

The inspected records shared:

- Rule ID `597`
- Description `Registry Key Entry Deleted.`
- Agent ID `001`
- Location `syscheck`

### Investigation

The `full_log` and related fields were inspected to compare the underlying registry paths.

The inspected events referenced different registry paths, including:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AarSvc_14eb4c
```

and:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\webthreatdefusersvc_14eb4c\Security
```

### Interpretation

The close timestamps justified further inspection, but the different paths meant the available evidence did not establish that these were duplicate copies of one event.

Do not label alerts as duplicates based only on matching rule IDs, descriptions, agents, or timestamps.

## 5. Source-IP Aggregation Was Not Suitable for the Observed Event

### Issue

The source-IP aggregation returned no buckets.

### Cause

The query required the `data.srcip` field to exist. The registry-deletion records under investigation were represented by `syscheck` event details rather than the source-IP pattern used by the query.

### Resolution

Group or filter the relevant event type using fields supported by the observed documents, such as:

- `rule.id`
- `agent.id`
- `location`
- `@timestamp`
- `full_log`

Only use a source-IP aggregation when the selected events actually contain a suitable source-IP field.

## 6. Interpreting the Total Alert Count

### Observation

The 24-hour search returned:

```json
{
  "value": 1411,
  "relation": "eq"
}
```

The top-rules aggregation also reported:

```json
{
  "sum_other_doc_count": 62
}
```

### Interpretation

The first result represents the total number of matching documents for that query at that time.

The `sum_other_doc_count` value represents documents belonging to terms outside the aggregation's returned top buckets. It is not the number of confirmed duplicate alerts.

Alert counts should be used to identify patterns for investigation, not as proof of duplicate ingestion.

