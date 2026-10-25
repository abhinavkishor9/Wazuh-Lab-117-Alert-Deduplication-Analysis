# Investigation Timeline

## Timeline of Activities

### 1. Verify Wazuh Alert Indices

**Activity:** Checked the available `wazuh-alerts-*` indices and queried recent alert documents.

**Evidence:**
- Alert indices included `wazuh-alerts-4.x-2026.10.24` and `wazuh-alerts-4.x-2026.10.25`.
- Recent alert documents were returned.
- The documents included agent information, rule details, and timestamps.

**Outcome:** Confirmed that the Wazuh alert data was available for investigation.

### 2. Identify Frequently Occurring Rules

**Activity:** Aggregated alert documents by `rule.id` over the previous 24 hours.

**Evidence:**
- Total matching documents: 1,411.
- The aggregation returned buckets for the most frequent rules.
- `sum_other_doc_count` was 62.

**Outcome:** Established an initial baseline and identified recurring rule activity for further investigation.

### 3. Attempt Source-IP-Based Grouping

**Activity:** Filtered the same time window for documents containing `data.srcip` and attempted to group the results by rule, agent, and source IP.

**Evidence:**
- Matching documents: 0.
- Aggregation buckets: empty.
- Failed shards: 0.

**Outcome:** The source-IP approach did not apply to the matching dataset. The investigation continued using fields available in the observed alerts.

### 4. Investigate Rule 597

**Activity:** Queried Rule `597`, `Registry Key Entry Deleted.`, and retrieved individual alert documents.

**Evidence:**
- Agent: `DESKTOP-9MMM37V`, ID `001`.
- Event location: `syscheck`.
- Event mode: `scheduled`.
- Several records occurred within milliseconds of one another.
- The inspected records referenced different registry paths.

**Outcome:** Confirmed recurring registry-deletion alerts. Duplicate ingestion was not established.

### 5. Examine the Alert Timeline

**Activity:** Reviewed event timestamps and considered a minute-level histogram to identify bursts of Rule `597` alerts.

**Evidence:**
- Closely spaced events appeared around 05:27 local time on 25 October 2026.
- Timestamp proximity alone did not establish that the events were duplicates.

**Outcome:** Identified a time-concentrated alert pattern requiring comparison of underlying event details.

### 6. Review Frequency and Suppression Settings

**Activity:** Connected to the Linux-based Wazuh Manager and searched the ruleset for `frequency`, `timeframe`, and `ignore`.

**Evidence:**
- The search returned matching definitions in multiple ruleset files.
- Examples included Windows base, Windows Security, Sysmon, Windows Defender, and firewall rules.

**Outcome:** Confirmed that frequency and suppression-related settings existed in the ruleset. The search did not establish whether Rule `597` used these settings.

### 7. Document Findings and Limitations

**Activity:** Consolidated query results, alert-field comparisons, configuration observations, and troubleshooting details.

**Outcome:**
- Recurring alert activity was documented.
- Duplicate ingestion remained unconfirmed.
- No alert documents were deleted.
- No rule configuration was modified.
- Further validation was identified as necessary before proposing deduplication or suppression changes.

