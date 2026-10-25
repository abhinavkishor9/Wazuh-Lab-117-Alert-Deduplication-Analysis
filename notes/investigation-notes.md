# Lab 117 — Investigation Notes

## 1. Investigation Objective

Analyze recurring Wazuh alerts to determine whether similar-looking records represent separate security events, repeated rule matches, or potential duplicate ingestion.

The investigation prioritizes the comparison of individual alert documents rather than treating high alert counts as proof of duplication.

## 2. Data Source and Environment

- Index pattern: `wazuh-alerts-*`
- Observed index: `wazuh-alerts-4.x-2026.10.24`
- Additional observed index: `wazuh-alerts-4.x-2026.10.25`
- Endpoint agent: `DESKTOP-9MMM37V` (`001`)
- Manager agent: `localhost.localdomain` (`000`)
- Investigation window: Previous 24 hours, based on query execution time

## 3. Alert Index Verification

### Query

```json
GET _cat/indices/wazuh-alerts-*?v
```

The alert indices were subsequently queried using:

```json
POST /wazuh-alerts-*/_search
{
  "size": 10,
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ],
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h",
        "lte": "now"
      }
    }
  },
  "_source": [
    "@timestamp",
    "timestamp",
    "rule.id",
    "rule.level",
    "rule.description",
    "agent.id",
    "agent.name",
    "data.srcip"
  ]
}
```

### Observation

The alert indices contained documents. The query response showed recent alerts from both the Wazuh manager and the Windows endpoint.

The returned documents included fields such as `@timestamp`, `timestamp`, `agent`, and `rule`. This confirmed that the index pattern was usable for further investigation.

## 4. Top Rule Analysis

### Query

```json
POST /wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h",
        "lte": "now"
      }
    }
  },
  "aggs": {
    "top_rules": {
      "terms": {
        "field": "rule.id",
        "size": 20,
        "order": {
          "_count": "desc"
        }
      },
      "aggs": {
        "rule_description": {
          "terms": {
            "field": "rule.description",
            "size": 1
          }
        }
      }
    }
  }
}
```

### Observation

The query completed successfully and returned 1,411 matching documents. The top-rules aggregation returned rule-count buckets, with 62 documents reported in `sum_other_doc_count` outside the returned top-rule buckets.

This provided a starting point for selecting recurring alert patterns for closer examination.

A high count identifies an investigation candidate; it does not prove that the underlying alerts are duplicates.

## 5. Source IP Aggregation

### Query

The investigation attempted to group alerts by rule, agent, and source IP, filtering for records containing `data.srcip`.

```json
POST /wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h",
              "lte": "now"
            }
          }
        },
        {
          "exists": {
            "field": "data.srcip"
          }
        }
      ]
    }
  },
  "aggs": {
    "by_rule": {
      "terms": {
        "field": "rule.id",
        "size": 20
      },
      "aggs": {
        "by_agent": {
          "terms": {
            "field": "agent.id",
            "size": 10
          },
          "aggs": {
            "by_source_ip": {
              "terms": {
                "field": "data.srcip",
                "size": 20
              }
            }
          }
        }
      }
    }
  }
}
```

### Observation

The query returned zero matching documents and an empty aggregation.

This indicated that no documents matched the query's time range and `data.srcip` existence filter. The result did not indicate an index failure.

The inspected registry-deletion alerts did not require source-IP grouping, so the investigation proceeded using rule ID, agent, timestamp, event location, and registry path.

## 6. Rule 597 Investigation

### Rule details

- Rule ID: `597`
- Description: `Registry Key Entry Deleted.`
- Agent ID: `001`
- Agent name: `DESKTOP-9MMM37V`
- Location: `syscheck`

### Query

```json
POST /wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "rule.id": "597"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h",
              "lte": "now"
            }
          }
        }
      ]
    }
  },
  "sort": [
    {
      "@timestamp": {
        "order": "asc"
      }
    }
  ],
  "_source": [
    "@timestamp",
    "timestamp",
    "agent.id",
    "agent.name",
    "rule.id",
    "rule.description",
    "location",
    "full_log",
    "data"
  ]
}
```

### Observed event evidence

One returned event contained the following details:

- Event timestamp: `2026-10-24T23:57:28.632Z`
- Local timestamp: `2026-10-25T05:27:28.632+0530`
- Rule ID: `597`
- Rule description: `Registry Key Entry Deleted.`
- Location: `syscheck`
- `syscheck.mode`: `scheduled`
- Registry path in `full_log`: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AarSvc_14eb4c`

Another inspected record showed the registry path:

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\webthreatdefusersvc_14eb4c\Security`

Its associated system-check metadata showed `syscheck.mode: scheduled`.

### Interpretation

The inspected alerts occurred close together and shared the same rule ID, agent, and event location. However, the registry paths differed.

This is evidence of recurring registry-deletion alerts, but it is not evidence that the same event was ingested multiple times.

The `syscheck.mode: scheduled` value also indicates that the inspected event was associated with scheduled system-check activity. The available records alone do not establish whether the underlying registry changes were expected, suspicious, or caused by a particular application.

## 7. Timestamp Analysis

The alert documents included closely spaced timestamps around `2026-10-25 05:27:29` local time.

Several inspected records were separated by milliseconds. This timing warranted comparison of the underlying event fields, but timing proximity alone was insufficient to establish duplication.

A minute-level date histogram was proposed to identify bursts of Rule `597` alerts. A burst can help locate activity for review, but it cannot independently determine whether the events are duplicates.

## 8. Rule Configuration Review

The ruleset search identified frequency, timeframe, and ignore attributes in multiple files under `/var/ossec/ruleset/rules/`.

Examples from the terminal output included:

- Rule `60013` in `0575-win-base_rules.xml`
- Rule `60203` in `0580-win-security_rules.xml`
- Rule `61642` in `0595-win-sysmon_rules.xml`
- Rule `62103` in `0600-win-wdefender_rules.xml`
- Rule `4151` in `0800-firewall_rules.xml`

These results confirm that the ruleset contains frequency-based detection and suppression-related settings.

They do not demonstrate that Rule `597` uses these settings, nor that suppression affected the observed registry-deletion alerts. That would require inspecting Rule `597` and its relevant rule relationships directly.

## 9. Findings and Limitations

### Confirmed

- Wazuh alert indices contained searchable documents.
- The 24-hour query returned 1,411 alert documents.
- Rule `597` produced recurring registry-deletion alerts.
- The inspected records contained different registry paths.
- The source-IP-filtered query returned zero documents.
- Frequency and suppression-related attributes existed in multiple ruleset files.

### Not established

- That the inspected alerts were duplicate ingestions.
- That the same underlying event was processed more than once.
- That Rule `597` has a suppression configuration.
- That suppression reduced the alert count.
- That the registry changes were malicious or benign.

## 10. Conclusion

The investigation identified a recurring Rule `597` alert pattern that merits contextual review. Because the inspected registry paths differed, the evidence supports recurring events more strongly than duplicate ingestion.

Further analysis should compare complete event details and, if duplication remains suspected, trace an individual source event through collection and indexing. No configuration changes are justified solely by the observed alert counts.
