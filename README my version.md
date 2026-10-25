# Lab 117 — Wazuh Alert Deduplication Analysis
## Overview
Wazuh stores generated alerts in the wazuh-alerts-* index, which can be searched through the Wazuh Dashboard's Dev Tools or Discover interface.

- Repeated activity: Multiple events occur because the same behavior happens repeatedly.
- Duplicate-looking alerts: Several alerts share similar fields, but may represent separate events.
- Repeated detection: The same detection rule matches multiple events over a short period.
- Alert suppression: A rule is configured to suppress repeated alerts for a specified period.
- Frequency-based detection: A rule evaluates multiple matching events within a time window before generating an alert.
These are not necessarily the same thing. Two alerts with the same rule ID and source IP are not automatically duplicates. They may represent two distinct events that require investigation.

This lab investigates recurring alerts in Wazuh to determine whether similar-looking alert records represent duplicate data, repeated detection activity, or separate security events occurring close together.

The investigation uses the Wazuh Indexer Dev Tools interface to search alert indices, identify frequently occurring detection rules, inspect individual alert documents, and group events by time. It also includes a read-only review of Wazuh rule definitions for frequency thresholds, time windows, and alert suppression settings.

The analysis focuses on evidence rather than assuming that repeated alerts are duplicates.

## Lab Objectives

- Understand the difference between recurring Wazuh alerts, duplicate-looking records, and confirmed duplicate ingestion.
- Query the `wazuh-alerts-*` indices to establish alert availability and identify frequently occurring detection rules.
- Analyze alert patterns by rule ID, agent, timestamp, event location, and underlying event details.
- Investigate Rule `597` registry-deletion alerts and compare registry paths to determine whether the records represent distinct events.
- Use aggregation queries to identify concentrated alert activity and recognize the limitations of timestamp-based comparisons.
- Investigate why source-IP-based aggregation may return no results when the selected events do not contain the expected field.
- Review Wazuh ruleset definitions for `frequency`, `timeframe`, and `ignore` settings.
- Distinguish configured suppression behavior from verified runtime behavior and measurable alert reduction.
- Document findings, troubleshooting steps, and evidence gaps without assuming that similar alerts are duplicates.
- Identify further validation required before recommending alert suppression or deduplication changes.

## Lab Scenario

A Wazuh environment can generate multiple alerts within a short period when monitored endpoints produce recurring security events. Although these alerts may share the same rule ID, agent, or description, they do not necessarily represent duplicate records. Treating every repeated alert as redundant could conceal meaningful activity and reduce the effectiveness of security monitoring.

In this lab, the analyst examines the `wazuh-alerts-*` indices to identify frequently occurring detection rules and investigate recurring alert patterns. The analysis focuses on Rule `597`, **Registry Key Entry Deleted**, which generated several closely timed alerts from the Windows endpoint `DESKTOP-9MMM37V`. Individual alert documents are compared using timestamps, agent details, event locations, and registry paths to determine what the available evidence supports.

The investigation also includes reviewing Wazuh ruleset definitions for `frequency`, `timeframe`, and `ignore` settings. These settings provide context for understanding repeated-event detection and alert suppression, but their presence in the ruleset does not prove that a particular alert was suppressed or that alert volume was reduced.

### Investigation Focus

- Identify recurring alerts and frequently matched detection rules.
- Compare underlying event details to distinguish separate events from suspected duplicate ingestion.
- Investigate why source-IP-based aggregation may not be useful for registry-monitoring events.
- Review frequency-based detection and suppression-related configuration.
- Document confirmed findings, unresolved questions, and evidence limitations.

The investigation is conducted using read-only queries and configuration review. No alerts are deleted, and no suppression settings are modified. The objective is to establish an evidence-based assessment of recurring alerts before recommending any deduplication or alert-noise reduction changes.
  
## Environment

- SIEM: Wazuh
- Data source: Wazuh alert indices
- Index pattern: `wazuh-alerts-*`
- Observed index examples:
  - `wazuh-alerts-4.x-2026.10.24`
  - `wazuh-alerts-4.x-2026.10.25`
- Query interface: Wazuh Indexer Dev Tools
- Manager access: Linux terminal
- Endpoint agent observed: `DESKTOP-9MMM37V`, agent ID `001`
- Manager agent observed: `localhost.localdomain`, agent ID `000`

## Investigation Summary

The initial alert search confirmed that the Wazuh alert indices contained data. A query covering the previous 24 hours returned 1,411 documents at the time of the investigation.

The top-rules aggregation identified recurring alert activity. A separate aggregation filtered for `data.srcip` returned zero documents, indicating that this field was not present in the matching dataset for that query and time window.

The investigation then focused on Rule `597`, described as `Registry Key Entry Deleted.` The returned records showed closely timed events from agent `001`, with `location` set to `syscheck`. The underlying records included different registry paths, so the available evidence did not establish that these alerts were duplicate events.

A read-only search of the Wazuh ruleset identified multiple rules containing frequency, timeframe, or ignore settings. These results demonstrated that such configuration options exist in the ruleset, but did not establish that Rule `597` uses suppression or that suppression affected the observed alerts.

## Key Findings

- Wazuh alert indices were available and returned documents successfully.
- The 24-hour search returned 1,411 alert documents during the investigation.
- Rule `597` generated closely timed registry-deletion alerts.
- The inspected alert records contained different registry paths.
- The source-IP aggregation returned no matching documents.
- Frequency and suppression settings were present in several ruleset files.
- Duplicate ingestion was not confirmed.
- No rule configuration was changed and no alert data was deleted.

## Investigation Approach

1. Verify that Wazuh alert indices contain documents.
2. Retrieve recent alerts and inspect available fields.
3. Aggregate alert counts by rule ID.
4. Investigate recurring alerts associated with Rule `597`.
5. Compare individual alert documents and their underlying event details.
6. Review rule configuration for frequency and suppression settings.
7. Document findings, limitations, and possible next steps.

