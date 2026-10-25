# Lab 117 — Wazuh Alert Deduplication Analysis

## Overview

This lab investigates recurring alerts in Wazuh to determine whether similar-looking alert records represent duplicate data, repeated detection activity, or separate security events occurring close together.

The investigation uses the Wazuh Indexer Dev Tools interface to search alert indices, identify frequently occurring detection rules, inspect individual alert documents, and group events by time. It also includes a read-only review of Wazuh rule definitions for frequency thresholds, time windows, and alert suppression settings.

The analysis focuses on evidence rather than assuming that repeated alerts are duplicates.

## Objectives

- Identify alert patterns within the available Wazuh alert data.
- Determine which detection rules generate recurring alerts.
- Compare timestamps, agent information, event locations, and underlying event details.
- Investigate repeated Rule `597` alerts associated with registry key deletion events.
- Understand the distinction between duplicate-looking alerts, repeated activity, frequency-based detection, and suppression.
- Review rule configuration for `frequency`, `timeframe`, and `ignore` settings.
- Record troubleshooting observations and document limitations.

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

## Conclusion

This lab demonstrates why alert counts alone are insufficient to establish duplication. Closely timed alerts can arise from separate events, and repeated matches against a rule do not automatically mean that duplicate data has entered the index.

The Rule `597` records examined in this investigation contained different registry paths. Based on the available evidence, the correct conclusion is that recurring registry-deletion alerts were observed, but duplicate ingestion was not proven.

Further validation would require examining the complete source events and, if duplicate ingestion remains suspected, tracing the same source event through collection, alert generation, and indexing.

## Safety and Scope

- All index queries were read-only.
- Rule configuration was inspected without modification.
- No alerts or index documents were deleted.
- No suppression settings were enabled or changed.
- No conclusion was drawn beyond the evidence returned by the queries.
