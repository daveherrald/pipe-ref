# SQL for Security Analysts

> A quick reference for analyzing security data with **Databricks SQL pipe syntax**, written for SOC analysts and detection engineers coming from Splunk SPL or Microsoft KQL.

[![Databricks SQL](https://img.shields.io/badge/Databricks-SQL%20Pipe%20Syntax-FF3621?logo=databricks&logoColor=white)](https://docs.databricks.com/en/sql/language-manual/sql-ref-syntax-qry-query.html#pipe-syntax)

[Databricks SQL](https://docs.databricks.com/en/sql/index.html) is a powerful query language for analyzing data at scale. This guide focuses on using Databricks SQL to analyze security data stored in security lakehouses, such as Databricks Lakewatch. We primarily focus on [SQL Pipe Syntax](https://docs.databricks.com/en/sql/language-manual/sql-ref-syntax-qry-query.html#pipe-syntax), an alternative syntax that makes queries easier to read and write by flowing from top to bottom, like a pipeline. Analysts familiar with Splunk SPL or Microsoft KQL should find this syntax familiar; however, Databricks SQL also supports traditional SQL syntax and offers options to quickly and easily convert natural language queries to SQL. This reference guide covers key concepts, operators, functions, and security-specific query examples.

_Independent community reference maintained by [Dave Herrald](https://github.com/daveherrald). This is not official Databricks or Lakewatch documentation; see the [official Databricks SQL docs](https://docs.databricks.com/en/sql/) and the [Lakewatch documentation](https://docs.lakewatch.com/) for the authoritative reference._

## Contents

- [The Databricks Lakewatch Environment](#the-databricks-lakewatch-environment)
  - [Where to Run SQL Queries](#where-to-run-sql-queries)
- [Concepts](#concepts)
  - [Events](#events)
  - [Tables](#tables)
  - [Common Security Patterns for `RLIKE`](#common-security-patterns-for-rlike)
  - [Implementation in SQL Pipe Syntax](#implementation-in-sql-pipe-syntax)
  - [SEARCH expression](#search-expression)
  - [Fields](#fields)
  - [Timestamps](#timestamps)
  - [OCSF (Open Cybersecurity Schema Framework)](#ocsf-open-cybersecurity-schema-framework)
  - [Search](#search)
  - [Detection rules](#detection-rules)
  - [Investigations](#investigations)
- [SQL Pipe Syntax](#sql-pipe-syntax)
  - [Additional Filtering](#additional-filtering)
- [Common Operators](#common-operators)
- [Common Functions](#common-functions)
  - [Comparison and Logic](#comparison-and-logic)
  - [Conditional Functions](#conditional-functions)
  - [String Functions](#string-functions)
  - [Numeric Functions](#numeric-functions)
- [Aggregate Functions](#aggregate-functions)
- [Window Functions](#window-functions)
  - [Example: Detecting Rapid Repeated Failures](#example-detecting-rapid-repeated-failures)
  - [Window Syntax](#window-syntax)
  - [Common Window Functions](#common-window-functions)
- [Time Functions](#time-functions)
  - [Current Time](#current-time)
  - [Time Filtering](#time-filtering)
  - [Time Extraction](#time-extraction)
  - [Time Bucketing](#time-bucketing)
  - [Time Arithmetic](#time-arithmetic)
  - [Time Formatting](#time-formatting)
- [Style Guide](#style-guide)
  - [Formatting](#formatting)
  - [Comments](#comments)
  - [Performance](#performance)
- [Regular Expressions](#regular-expressions)
- [Working with IP addresses](#working-with-ip-addresses)
- [Query Examples](#query-examples)
  - [Filter Events](#filter-events)
  - [Order Results](#order-results)
  - [Add Computed Fields](#add-computed-fields)
  - [Select and Remove Fields](#select-and-remove-fields)
  - [Group and Count](#group-and-count)
  - [Top and Rare Values](#top-and-rare-values)
  - [Time-Based Analysis](#time-based-analysis)
  - [Join Tables](#join-tables)
  - [Sequence Detection](#sequence-detection)
  - [Parsing Data with `regexp_extract()`](#parsing-data-with-regexp_extract)
  - [Why use `regexp_extract()`?](#why-use-regexp_extract)
  - [Syntax](#syntax)
- [Security Detection Examples](#security-detection-examples)
  - [Failed Login Threshold](#failed-login-threshold)
  - [Account Enumeration](#account-enumeration)
  - [Brute Force Success](#brute-force-success)
  - [Off-Hours Activity](#off-hours-activity)
  - [High-Volume Data Transfer](#high-volume-data-transfer)
  - [Activity From a Watchlisted Subnet](#activity-from-a-watchlisted-subnet)
  - [Suspicious Process Execution](#suspicious-process-execution)
  - [Rare Process Detection](#rare-process-detection)
  - [DNS Tunneling Indicator](#dns-tunneling-indicator)
  - [Threat Intelligence Match](#threat-intelligence-match)

---

## The Databricks Lakewatch Environment

Lakewatch is a security analytics platform built on Databricks. It provides a unified environment for cost-effectively ingesting, normalizing, enriching, searching, analyzing, and visualizing security data at scale. These capabilities allow security teams to consolidate and correlate logs, detect and investigate incidents, accelerate incident response, demonstrate compliance, and increase AI adoption in the SOC and beyond. Security telemetry from across your organization's environment (including endpoints, networks, cloud services, identity and access management systems, applications, etc.) flows into Lakewatch, where the security analyst interacts with it. In Lakewatch, security analysts use SQL as the query language to interact with their security data, and [Databricks Genie](https://docs.databricks.com/en/genie/index.html) makes that approachable at any SQL skill level.

### Where to Run SQL Queries

The queries in this guide work in multiple places across Lakewatch and the broader Databricks Platform:

- [**Lakewatch Query Interface**](https://docs.lakewatch.com/threat-detection/query-page): Purpose-built for security investigations
- [**Databricks SQL Editor**](https://docs.databricks.com/en/sql/user/sql-editor/index.html): Full-featured SQL IDE with autocomplete and visualization
- [**Databricks Notebooks**](https://docs.databricks.com/en/notebooks/index.html): Interactive analysis combining SQL, Python, and markdown documentation

Queries will generally produce identical core results regardless of which of these interfaces you choose.

One notable exception is the time range. The Lakewatch Query Interface ties every query to its date/time picker, so each query must include a time filter that uses the picker values, written either as `WHERE time BETWEEN :start AND :end` or the shorthand `WHERE inRange(time)`, plus `ORDER BY time`. Omit them and the query runs on all data. The Databricks SQL Editor has no such picker, so you set the window explicitly, for example `WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS`.

SQL is also used in Lakewatch detection rules. It's common to develop and test queries in the SQL Editor, Query Interface, or Notebooks, before incorporating them into Lakewatch detection rules.

**Genie** lets you query the same data conversationally. Because Genie generates standard Databricks SQL, the operators, functions, and patterns in this guide apply directly to what it produces, whether you read its SQL to learn, adjust it by hand, or ask Genie to refine the query for you.

---

## Concepts

### Events

An event is a security log entry associated with a timestamp. It is a single record and can represent authentication attempts, network connections, process executions, file access, and more.

**Raw Event Example (excerpt):**

```json
{
  "Id": 4624,
  "TimeCreated": "2026-01-06T03:34:29.379Z",
  "ProviderName": "Microsoft-Windows-Security-Auditing",
  "LogName": "Security",
  "MachineName": "rex.internal.example",
  "TargetUserName": "REX$",
  "TargetDomainName": "INTERNAL",
  "TargetUserSid": "S-1-5-18",
  "TargetLogonId": "0xfc03fb",
  "IpAddress": "10.0.1.45",
  "LogonType": 3,
  "LogonProcessName": "Kerberos"
}
```

Raw events arrive in their original format (JSON, XML, CSV, string/syslog, etc.) and are stored in bronze tables. After normalization to [OCSF](https://schema.ocsf.io/) (more on this later), the same event will be stored in a gold table with standardized field names that work regardless of the event's source.

**Normalized Event (from OCSF/Gold `authentication` table)**

| OCSF Field | Value |
| :---- | :---- |
| **time** | 2026-01-06 03:34:29.379 |
| **user.name** | REX$ |
| **user.uid** | S-1-5-18 |
| **src_endpoint.ip** | 10.0.1.45 |
| **auth.type_id** | 3 |
| **auth.logon_id** | 0xfc03fb |
| **metadata.event_code** | 4624 |

### Tables

Tables store security event data in a structured format with rows and columns. Each row is an event, and each column is a field. In Lakewatch, tables are organized in a three-level namespace: **catalog.schema.table**. The examples in this guide use `lakewatch` as the catalog name, with schemas that represent the medallion architecture or different processing stages:

| Schema | Description | Table Names |
| :---- | :---- | :---- |
| `bronze` | Raw data in its native format | Named by data source: `aws_cloudtrail`, `crowdstrike_events`, `zeek_conn`, `microsoft_winevtlog` |
| `silver` | Enriched and cleaned data with field names derived from the original raw event | Not persisted by default |
| `gold` | Normalized to OCSF schema | Named by OCSF class: `authentication`, `network_activity`, `dns_activity`, `process_activity` |

**Bronze tables and VARIANT type:** Raw security data arrives in many formats, such as JSON, plain text strings, or other structures. Bronze tables typically store this data using the [VARIANT data type](https://docs.databricks.com/en/sql/language-manual/data-types/variant-type.html), which can hold any type and preserves the original structure without requiring a predefined schema. You query VARIANT columns with the colon operator (e.g., `data:eventName`), and cast the extracted value with `::` (e.g., `data:eventName::STRING`). Dot notation applies to STRUCT columns and normalized gold fields such as `actor.user.name`, not to VARIANT. This flexibility is valuable when exploring new data sources or accessing fields that haven't been normalized to OCSF.

**Searching raw logs:** In Lakewatch bronze tables like the ones in this guide, the raw log usually sits in a field called `data`, typically a VARIANT. You can search it with pattern matching or with Lakewatch's full-text [`SEARCH` expression](#search-expression):

- `LIKE`: Simple wildcard matching (`%` matches any characters)
- `RLIKE`: Regular expression matching for complex patterns
- `SEARCH`: Indexed full-text matching that reads the VARIANT directly, with no `CAST` needed

```sql
-- Pattern match on the raw text (CAST to string first)
FROM lakewatch.bronze.microsoft_winevtlog
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> WHERE CAST(data AS STRING) LIKE '%mimikatz%'

-- Full-text match on the same VARIANT, no CAST
FROM lakewatch.bronze.microsoft_winevtlog
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> WHERE SEARCH(data, 'mimikatz')
```

**Pattern Matching with `RLIKE`**

While SQL uses `LIKE` for simple wildcard matching (e.g., `user_name LIKE 'admin%'`), security analysis often requires more precision. Databricks SQL implements the `RLIKE` operator, which uses Java-style Regular Expressions (RegEx) to find complex patterns in logs.

**Why use `RLIKE`?**

* **Case Insensitivity:** Easily find `Mimikatz`, `MIMIKATZ`, or `mImIkAtZ`.
* **Complex Strings:** Find hashes, encoded commands, or specific IP subnets.
* **Flexibility:** Search for multiple variations of a threat in a single line.

### Common Security Patterns for `RLIKE`

| Goal | RegEx Pattern | Description |
| :---- | :---- | :---- |
| **Case Insensitivity** | `(?i)pattern` | The `(?i)` flag makes the match ignore case. |
| **Hashes (MD5/SHA)** | `[a-f0-9]{32,}` | Matches 32 or more hexadecimal characters. |
| **Suspicious Files** | `\.(vbs\|ps1\|bat\|exe)$` | Matches files ending in specific "dangerous" extensions. |
| **Obfuscated CLI** | `[\^+]` | Detects characters like `^` or `+` used to break up commands. |
| **Machine Accounts** | `.*\$$` | Matches any string ending in a dollar sign (Windows machine accounts). |

### Implementation in SQL Pipe Syntax

In the Pipe Syntax, `RLIKE` is most powerful when used inside a `WHERE` or `EXTEND` operator.

**Finding Encoded PowerShell Commands:**

```sql
FROM lakewatch.gold.process_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE process_name RLIKE '(?i)powershell\.exe'
   AND cmd_line RLIKE '-e[ncod]*\s+[A-Za-z0-9+/=]{20,}'
```

### SEARCH expression

Lakewatch adds a built-in [`SEARCH` expression](https://docs.lakewatch.com/threat-detection/search-expression) for full-text matching across columns, backed by a prebuilt index. `ISEARCH` is the case-insensitive form. It complements `LIKE` and `RLIKE`, and is often the simplest way to find a value without writing a pattern.

```
SEARCH(col1, col2, ..., search_pattern [, mode => 'substring' | 'word' | 'ip'])
```

Searchable columns are STRING, VARIANT, STRUCT, and ARRAY types, and `*` searches every searchable column in the table. The `mode` argument defaults to `substring` (equivalent to `CONTAINS`); `word` matches whole tokens, and `ip` matches an IPv4 address or CIDR range.

```sql
-- Any searchable column mentions mimikatz
FROM lakewatch.bronze.crowdstrike_events
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE SEARCH(*, 'mimikatz')

-- Source IP within a subnet, no regex required
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE SEARCH(src_endpoint.ip, '10.0.0.0/24', mode => 'ip')

-- Case-insensitive whole-word match
FROM lakewatch.bronze.microsoft_winevtlog
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE ISEARCH(data, 'PsExec', mode => 'word')
```

### Fields

Fields are the columns in a table that contain specific attributes of an event. Field names vary by layer:

- **Bronze**: All fields are embedded in the `data` column of the table. A faithful preservation of the original data.
- **Silver**: Field names defined by the original data source
- **Gold**: Normalized to [OCSF](https://schema.ocsf.io/) field names

Common OCSF fields in gold tables:

| Field | Description |
| :---- | :---- |
| `time` | When the event occurred (timestamp) |
| `activity_id` / `activity_name` | What happened (Logon, Create, Connect, etc.) |
| `status` | Success, Failure, or other outcome |
| `severity` | Event severity level |
| `src_endpoint` | Source device (struct with ip, hostname, domain) |
| `dst_endpoint` | Destination device (struct with ip, hostname, domain) |
| `actor.user.name` | Username performing the action |
| `metadata` | Event metadata (log source, event code) |

### Timestamps

Every security event has a timestamp indicating when it occurred. In Lakewatch, the field `time` is standard across all tables. You can always filter and sort by `time` regardless of which table you're querying.

Timestamps are essential for:

- Filtering events to specific time windows
- Ordering events chronologically during investigations
- Correlating related events across different data sources
- Building time-series visualizations

### OCSF (Open Cybersecurity Schema Framework)

[OCSF](https://schema.ocsf.io/) is an open standard for normalizing security data from different sources. When data is normalized to OCSF, standard field names are used regardless of the original source, making it easier to write queries that work across multiple data types. See the [OCSF schema browser](https://schema.ocsf.io/classes) for the complete list of event classes and their fields.

### Search

Search is a common tool when investigating security data. You write queries to retrieve events from tables, filter for specific conditions, calculate statistics, identify patterns, and generate reports. Queries are written in SQL, including the pipe syntax this guide focuses on, and the same logic can be reused when authoring detection rules.

### Detection rules

Detection rules are saved queries that run on a schedule to identify security threats. When a rule matches, it generates a notable/case. Detection rules can identify known attack patterns, anomalous behavior, policy violations, and compliance issues.

### Investigations

When a notable/case fires or suspicious activity is reported, analysts use ad-hoc queries to investigate. The linear nature of pipe syntax makes it easy to iteratively refine queries during an investigation, adding filters, computing new fields, and drilling down into the data.

---

## SQL Pipe Syntax

[SQL Pipe Syntax](https://docs.databricks.com/en/sql/language-manual/sql-ref-syntax-qry-query.html#pipe-syntax) transforms traditional SQL into a linear, top-to-bottom flow. A query is a series of operators connected by the pipe symbol `|>`. Each operator takes a table as input and produces a table as output, which flows to the next operator.

```sql
FROM table
|> operator1
|> operator2
|> ...
```

The query begins with `FROM` to specify the source table. Each subsequent `|>` operator transforms the data. The operators execute in order from top to bottom, making the data flow easy to follow.

**Example:** Retrieve failed login events and count them by user:

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE status = 'Failure'
|> AGGREGATE COUNT(*) AS failures GROUP BY actor.user.name
```

This query starts with the authentication table, filters to only failed events, then counts failures per user.

### Additional Filtering

Beyond time filtering, add specific conditions to further reduce the data scanned:

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> WHERE dst_endpoint.port = 443
|> WHERE traffic.bytes_out > 1000000
```

Each `WHERE` clause narrows the result set. Place the most selective filters first.

---

## Common Operators

| Operator | Description |
| :---- | :---- |
| `FROM` | Starts the query with a source table. |
| `WHERE` | Filters rows based on a condition. Can be used multiple times. |
| `SELECT` | Chooses which columns to keep. Removes all others. |
| `EXTEND` | Adds new computed columns while keeping all existing columns. |
| `SET` | Modifies the values of existing columns. |
| `DROP` | Removes specified columns from results. |
| `AGGREGATE ... GROUP BY` | Computes statistics, optionally grouped by fields. |
| `ORDER BY` | Sorts results. Use `DESC` (descending) or `ASC` (ascending). |
| `LIMIT` | Returns only the first N rows. |
| `JOIN` | Combines data from two tables based on matching fields. |
| `AS` | Assigns an alias to the intermediate result for use in joins. |

---

## Common Functions

For a complete list of built-in functions, see the [Databricks SQL function reference](https://docs.databricks.com/en/sql/language-manual/sql-ref-functions-builtin.html).

### Comparison and Logic

These operators build the conditions in a query. You use them most often in `WHERE` to filter rows, and also in `JOIN ... ON` conditions, in `EXTEND` and `SET` expressions, and inside `IF()` and `CASE WHEN`.

| Function | Description | Example |
| :---- | :---- | :---- |
| `=` | Equals | `status = 'failed'` |
| `!=` or `<>` | Not equals | `status != 'success'` |
| `>`, `<`, `>=`, `<=` | Comparisons | `bytes > 1000` |
| `AND` | Both conditions true | `status = 'failed' AND user = 'admin'` |
| `OR` | Either condition true | `port = 22 OR port = 3389` |
| `NOT` | Negates condition | `NOT status = 'success'` |
| `IN (...)` | Matches any value in list | `port IN (22, 23, 3389)` |
| `BETWEEN` | Within range (inclusive) | `port BETWEEN 1 AND 1024` |
| `IS NULL` | Value is missing | `user IS NULL` |
| `IS NOT NULL` | Value exists | `source_ip IS NOT NULL` |
| `LIKE` | Pattern match (% = wildcard) | `user LIKE 'admin%'` |
| `RLIKE` | Regular expression match | `process.name RLIKE '(?i)mimikatz'` |
| `SEARCH(cols, 'x' [, mode])` | Indexed full-text match (substring/word/ip) | `SEARCH(*, 'mimikatz')` |

**Case Sensitivity:** String comparisons in SQL are case-sensitive by default. `'Failure'` does not equal `'failure'`. Use `LOWER()` or `UPPER()` to normalize case when needed:

```sql
|> WHERE LOWER(status) = 'failure'
```

Column names are generally case-insensitive, but string values in data must match exactly.

### Conditional Functions

| Function | Description | Example |
| :---- | :---- | :---- |
| `IF(cond, then, else)` | Returns value based on condition | `IF(status='success', 1, 0)` |
| `CASE WHEN ... THEN ... END` | Multiple conditions | See examples below |
| `COALESCE(a, b, ...)` | Returns first non-null value | `COALESCE(user, 'unknown')` |
| `NULLIF(a, b)` | Returns NULL if a equals b | `NULLIF(port, 0)` |

**CASE Example:**

```sql
|> EXTEND severity = CASE
    WHEN failures >= 10 THEN 'critical'
    WHEN failures >= 5 THEN 'high'
    WHEN failures >= 3 THEN 'medium'
    ELSE 'low'
   END
```

### String Functions

| Function | Description | Example |
| :---- | :---- | :---- |
| `LOWER(s)` | Convert to lowercase | `LOWER(username)` |
| `UPPER(s)` | Convert to uppercase | `UPPER(hostname)` |
| `LENGTH(s)` | Character count | `LENGTH(command_line)` |
| `CONCAT(a, b, ...)` | Join strings | `CONCAT(first, ' ', last)` |
| `SUBSTRING(s, start, len)` | Extract portion | `SUBSTRING(hash, 1, 8)` |
| `TRIM(s)` | Remove whitespace | `TRIM(user)` |
| `REPLACE(s, old, new)` | Replace text | `REPLACE(path, '\\', '/')` |
| `SPLIT(s, delim)` | Split into array | `SPLIT(tags, ',')` |
| `REGEXP_EXTRACT(s, pattern, group)` | Extract regex match | `REGEXP_EXTRACT(url, 'host=([^&]+)', 1)` |
| `REGEXP_REPLACE(s, pattern, repl)` | Replace regex match | `REGEXP_REPLACE(msg, '\\d+', 'X')` |

### Numeric Functions

| Function | Description | Example |
| :---- | :---- | :---- |
| `ABS(n)` | Absolute value | `ABS(delta)` |
| `ROUND(n, decimals)` | Round to precision | `ROUND(ratio, 2)` |
| `CEIL(n)` | Round up | `CEIL(score)` |
| `FLOOR(n)` | Round down | `FLOOR(score)` |
| `MOD(n, divisor)` | Remainder | `MOD(port, 1000)` |
| `POWER(n, exp)` | Exponentiation | `POWER(2, 10)` |
| `LOG(n)` | Natural logarithm | `LOG(bytes)` |
| `LOG10(n)` | Base-10 logarithm | `LOG10(bytes)` |

---

## Aggregate Functions

[Aggregate functions](https://docs.databricks.com/en/sql/language-manual/sql-ref-functions-builtin.html#aggregate-functions) compute statistics across multiple rows. Use them with the `AGGREGATE` operator.

| Function | Description |
| :---- | :---- |
| `COUNT(*)` | Count of all rows |
| `COUNT(field)` | Count of non-null values |
| `COUNT(DISTINCT field)` | Count of unique values |
| `SUM(field)` | Total of values |
| `AVG(field)` | Average of values |
| `MIN(field)` | Minimum value |
| `MAX(field)` | Maximum value |
| `FIRST(field)` | First value encountered |
| `LAST(field)` | Last value encountered |
| `COLLECT_LIST(field)` | All values as an array |
| `COLLECT_SET(field)` | Unique values as an array |
| `PERCENTILE(field, p)` | Value at percentile p (0-1) |
| `STDDEV(field)` | Standard deviation |
| `VARIANCE(field)` | Variance |

**Example:** Count events and unique IPs by user:

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE
    COUNT(*) AS total_events,
    COUNT(DISTINCT src_endpoint.ip) AS unique_ips,
    MIN(time) AS first_seen,
    MAX(time) AS last_seen
    GROUP BY actor.user.name
```

---

## Window Functions

[Window functions](https://docs.databricks.com/en/sql/language-manual/sql-ref-functions-builtin.html#window-functions) let you look at related rows while keeping every row in your results. This is different from `AGGREGATE`, which collapses rows into groups.

**Why this matters for security:** Window functions let you compare each event to what came before or after. You can detect patterns like "failed login followed by success" or calculate time gaps between events, without losing the individual event details you need for investigation.

### Example: Detecting Rapid Repeated Failures

Suppose you want to find failed logins that happened within seconds of each other for the same user. You need to compare each event's timestamp to the previous one.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE status = 'Failure'
|> EXTEND prev_time = LAG(time, 1) OVER (PARTITION BY actor.user.name ORDER BY time)
|> EXTEND seconds_since_prev = UNIX_TIMESTAMP(time) - UNIX_TIMESTAMP(prev_time)
|> WHERE seconds_since_prev < 5
```

**How it works:** `LAG(time, 1)` gets the timestamp from the previous row. `PARTITION BY actor.user.name` restarts the comparison for each user. `ORDER BY time` ensures rows are in chronological order.

**Input data:**

| time | actor.user.name | status |
| :---- | :---- | :---- |
| 2026-01-21 14:00:01 | jsmith | Failure |
| 2026-01-21 14:00:02 | jsmith | Failure |
| 2026-01-21 14:00:03 | jsmith | Failure |
| 2026-01-21 14:00:15 | jsmith | Failure |

**After EXTEND with LAG:**

| time | actor.user.name | status | prev_time | seconds_since_prev |
| :---- | :---- | :---- | :---- | :---- |
| 2026-01-21 14:00:01 | jsmith | Failure | NULL | NULL |
| 2026-01-21 14:00:02 | jsmith | Failure | 2026-01-21 14:00:01 | 1 |
| 2026-01-21 14:00:03 | jsmith | Failure | 2026-01-21 14:00:02 | 1 |
| 2026-01-21 14:00:15 | jsmith | Failure | 2026-01-21 14:00:03 | 12 |

**Final output (WHERE seconds_since_prev < 5):**

| time | actor.user.name | seconds_since_prev |
| :---- | :---- | :---- |
| 2026-01-21 14:00:02 | jsmith | 1 |
| 2026-01-21 14:00:03 | jsmith | 1 |

The rapid-fire failures (1 second apart) are flagged. The 12-second gap is filtered out.

### Window Syntax

```sql
function() OVER (
    PARTITION BY grouping_field    -- Reset for each group
    ORDER BY ordering_field        -- Row sequence
)
```

### Common Window Functions

| Function | Description |
| :---- | :---- |
| `LAG(field, n) OVER (...)` | Value from n rows before |
| `LEAD(field, n) OVER (...)` | Value from n rows after |
| `ROW_NUMBER() OVER (...)` | Sequential row number |
| `RANK() OVER (...)` | Rank with gaps for ties |
| `FIRST_VALUE(field) OVER (...)` | First value in window |
| `LAST_VALUE(field) OVER (...)` | Last value in window |
| `SUM(field) OVER (...)` | Running sum |
| `COUNT(*) OVER (...)` | Running count |

---

## Time Functions

For a complete list of date and time functions, see the [Databricks SQL datetime functions reference](https://docs.databricks.com/en/sql/language-manual/sql-ref-functions-builtin.html#date-and-time-functions).

### Current Time

| Function | Description |
| :---- | :---- |
| `CURRENT_TIMESTAMP()` | Current date and time |
| `CURRENT_DATE()` | Current date only |

### Time Filtering

In the Lakewatch Query Interface, the time window comes from the date/time picker, which you reference with `WHERE time BETWEEN :start AND :end` or the shorthand `WHERE inRange(time)`. The explicit intervals below are for setting the window yourself in the SQL Editor or notebooks.

```sql
-- Last 24 hours
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS

-- Last 7 days
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 7 DAYS

-- Last 30 minutes
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 30 MINUTES

-- Specific date range
|> WHERE time BETWEEN '2026-01-01' AND '2026-01-31'

-- Today only
|> WHERE DATE(time) = CURRENT_DATE()
```

### Time Extraction

| Function | Description | Example Output |
| :---- | :---- | :---- |
| `DATE(ts)` | Extract date | 2026-01-21 |
| `YEAR(ts)` | Extract year | 2026 |
| `MONTH(ts)` | Extract month (1-12) | 1 |
| `DAY(ts)` | Extract day (1-31) | 21 |
| `HOUR(ts)` | Extract hour (0-23) | 14 |
| `MINUTE(ts)` | Extract minute (0-59) | 30 |
| `SECOND(ts)` | Extract second (0-59) | 45 |
| `DAYOFWEEK(ts)` | Day of week (1=Sun, 7=Sat) | 3 |
| `DAYOFYEAR(ts)` | Day of year (1-366) | 21 |

### Time Bucketing

| Function | Description | Example Output |
| :---- | :---- | :---- |
| `DATE_TRUNC('HOUR', ts)` | Truncate to hour | 2026-01-21 14:00:00 |
| `DATE_TRUNC('DAY', ts)` | Truncate to day | 2026-01-21 00:00:00 |
| `DATE_TRUNC('WEEK', ts)` | Truncate to week | 2026-01-20 00:00:00 |
| `DATE_TRUNC('MONTH', ts)` | Truncate to month | 2026-01-01 00:00:00 |

### Time Arithmetic

| Function | Description |
| :---- | :---- |
| `ts + INTERVAL n HOURS` | Add hours |
| `ts - INTERVAL n DAYS` | Subtract days |
| `TIMESTAMPDIFF(unit, start, end)` | Difference between times |
| `DATEDIFF(end, start)` | Difference in days |
| `UNIX_TIMESTAMP(ts)` | Convert to epoch seconds |
| `FROM_UNIXTIME(epoch)` | Convert from epoch seconds |

### Time Formatting

| Pattern | Description | Example |
| :---- | :---- | :---- |
| `yyyy` | 4-digit year | 2026 |
| `MM` | Month (01-12) | 01 |
| `dd` | Day (01-31) | 21 |
| `HH` | Hour 24h (00-23) | 14 |
| `mm` | Minute (00-59) | 30 |
| `ss` | Second (00-59) | 45 |
| `EEEE` | Day name | Tuesday |
| `MMM` | Month abbrev | Jan |

```sql
|> EXTEND formatted = DATE_FORMAT(time, 'yyyy-MM-dd HH:mm:ss')
```

---

## Style Guide

### Formatting

Start with `FROM` on its own line. Align `|>` operators vertically. Use blank lines to separate logical sections.

```sql
FROM lakewatch.gold.authentication

|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE status = 'Failure'

|> AGGREGATE COUNT(*) AS failures GROUP BY actor.user.name

|> WHERE failures >= 5
|> ORDER BY failures DESC
```

### Comments

Add comments using `--` to explain complex logic.

```sql
FROM lakewatch.gold.authentication

-- Filter to recent failed logins only
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE status = 'Failure'

-- Count failures per user
|> AGGREGATE COUNT(*) AS failures GROUP BY actor.user.name

-- Alert threshold: 5+ failures
|> WHERE failures >= 5
```

### Performance

Security data tables can contain billions of rows. Follow these practices to write efficient queries:

**Always filter by time.** Every query should include a time range filter as early as possible. This is the single most important optimization. It determines how much data gets scanned.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
```

**Order by time for investigations.** When reviewing events chronologically, sort by the `time` field. Use `DESC` for most recent first, `ASC` for oldest first.

```sql
|> ORDER BY time DESC
```

**Use LIMIT during exploration.** When building or testing queries, add `LIMIT` to return a small sample quickly. Remove it only when you need complete results.

```sql
|> LIMIT 100
```

**Combine all three for fast, focused queries:**

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> WHERE status = 'Failure'
|> ORDER BY time DESC
|> LIMIT 100
```

---

## Regular Expressions

[Regular expressions](https://docs.databricks.com/en/sql/language-manual/functions/rlike.html) are patterns for matching text. Use them with `RLIKE`, `REGEXP_EXTRACT()`, and `REGEXP_REPLACE()`.

| Pattern | Matches | Example |
| :---- | :---- | :---- |
| `.` | Any single character | `a.c` matches "abc" |
| `*` | Zero or more of previous | `ab*c` matches "ac", "abc", "abbc" |
| `+` | One or more of previous | `ab+c` matches "abc", "abbc" |
| `?` | Zero or one of previous | `ab?c` matches "ac", "abc" |
| `^` | Start of string | `^admin` matches "admin123" |
| `$` | End of string | `\.exe$` matches "cmd.exe" |
| `[abc]` | Any character in set | `[aeiou]` matches vowels |
| `[^abc]` | Any character not in set | `[^0-9]` matches non-digits |
| `[a-z]` | Character range | `[A-Za-z]` matches letters |
| `\d` | Digit (0-9) | `\d{3}` matches "123" |
| `\w` | Word character (a-z, 0-9, _) | `\w+` matches "user_1" |
| `\s` | Whitespace | `\s+` matches spaces/tabs |
| `\|` | Alternation (or) | `cat\|dog` matches "cat" or "dog" |
| `(...)` | Grouping | `(ab)+` matches "abab" |
| `(?i)` | Case insensitive | `(?i)admin` matches "ADMIN" |

**Examples:**

Extract an IP address from a raw message.

```sql
|> EXTEND src_ip = REGEXP_EXTRACT(CAST(data AS STRING), '(\\d{1,3}(?:\\.\\d{1,3}){3})', 1)
```

Extract username from email.

```sql
|> EXTEND username = REGEXP_EXTRACT(actor.user.email_addr, '^([^@]+)@', 1)
```

Match common attack tool names.

```sql
|> WHERE process.cmd_line RLIKE '(?i)(mimikatz|psexec|cobalt)'
```

---

## Working with IP addresses

IP and subnet matching is common in security queries. Use `SEARCH` with `mode => 'ip'` rather than regular expressions. It understands IPv4, IPv6, and CIDR ranges, so you avoid brittle text patterns. In gold tables the addresses are in `src_endpoint.ip` and `dst_endpoint.ip`.

```sql
-- Exact address
|> WHERE SEARCH(src_endpoint.ip, '203.0.113.10', mode => 'ip')

-- Anything in a subnet (IPv4 or IPv6 CIDR)
|> WHERE SEARCH(src_endpoint.ip, '10.0.0.0/8', mode => 'ip')

-- Check both source and destination at once
|> WHERE SEARCH(src_endpoint.ip, dst_endpoint.ip, '203.0.113.0/24', mode => 'ip')
```

Reserve regular expressions for pulling an IP out of unstructured text, where `regexp_extract()` is the right tool.

---

## Query Examples

### Filter Events

Return authentication events from the last hour.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
```

Return failed login attempts for a specific user.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE status = 'Failure'
|> WHERE actor.user.name = 'jsmith'
```

Return events matching multiple conditions.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE dst_endpoint.port IN (22, 23, 3389)
|> WHERE traffic.bytes_out > 10000
```

Return events where the command line contains suspicious patterns.

```sql
FROM lakewatch.gold.process_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE process.cmd_line RLIKE '(?i)(mimikatz|procdump|lsass)'
```

### Order Results

Return the most recent 100 events.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> ORDER BY time DESC
|> LIMIT 100
```

Sort by multiple fields.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> ORDER BY actor.user.name ASC, time DESC
```

### Add Computed Fields

Calculate total bytes transferred.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND total_bytes = traffic.bytes_out + traffic.bytes_in
```

Extract the hour of day for pattern analysis.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND hour_of_day = HOUR(time)
```

Classify events by severity.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND severity_label = CASE
    WHEN severity >= 80 THEN 'critical'
    WHEN severity >= 60 THEN 'high'
    WHEN severity >= 40 THEN 'medium'
    ELSE 'low'
   END
```

### Select and Remove Fields

Keep only specific fields for output.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> SELECT time, actor.user.name, src_endpoint.ip, status
```

Remove sensitive fields before sharing results.

```sql
FROM lakewatch.gold.user_access
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> DROP unmapped.sensitive_field, metadata.data
```

### Group and Count

Count events by user.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE COUNT(*) AS event_count GROUP BY actor.user.name
```

| actor.user.name | event_count |
| :---- | :---- |
| svc_backup | 4521 |
| jsmith | 892 |
| admin | 445 |
| mwilson | 234 |

Count unique source IPs per destination.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE COUNT(DISTINCT src_endpoint.ip) AS unique_sources GROUP BY dst_endpoint.ip
```

Calculate multiple statistics.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE
    COUNT(*) AS connections,
    SUM(traffic.bytes_out) AS total_sent,
    AVG(duration) AS avg_duration
    GROUP BY src_endpoint.ip
```

### Top and Rare Values

Find the 20 most active users.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE COUNT(*) AS event_count GROUP BY actor.user.name
|> ORDER BY event_count DESC
|> LIMIT 20
```

| actor.user.name | event_count |
| :---- | :---- |
| svc_backup | 12847 |
| svc_monitoring | 8932 |
| jsmith | 2341 |
| admin | 1876 |
| mwilson | 1245 |

Find rarely executed processes.

```sql
FROM lakewatch.gold.process_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE COUNT(*) AS exec_count GROUP BY process.name
|> ORDER BY exec_count ASC
|> LIMIT 20
```

### Time-Based Analysis

Count events per hour.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND hour = DATE_TRUNC('HOUR', time)
|> AGGREGATE COUNT(*) AS events GROUP BY hour
|> ORDER BY hour
```

Compare weekday vs weekend activity.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND is_weekend = DAYOFWEEK(time) IN (1, 7)
|> AGGREGATE COUNT(*) AS events GROUP BY is_weekend
```

### Join Tables

Enrich events with threat intelligence.

```sql
FROM lakewatch.gold.network_activity AS n
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> JOIN threat_intel AS t ON n.dst_endpoint.ip = t.indicator
|> SELECT n.time, n.src_endpoint.ip, n.dst_endpoint.ip, t.threat_type, t.confidence
```

Add user context from directory.

```sql
FROM lakewatch.gold.authentication AS a
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> JOIN user_directory AS u ON a.actor.user.name = u.username
|> EXTEND department = u.department, manager = u.manager
```

### Sequence Detection

Find events where status changed from failed to success.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND prev_status = LAG(status, 1) OVER (PARTITION BY actor.user.name ORDER BY time)
|> WHERE status = 'Success' AND prev_status = 'Failure'
```

Calculate time between consecutive events.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND prev_time = LAG(time, 1) OVER (PARTITION BY actor.user.name ORDER BY time)
|> EXTEND seconds_since_prev = UNIX_TIMESTAMP(time) - UNIX_TIMESTAMP(prev_time)
```

### Parsing Data with `regexp_extract()`

While `RLIKE` is used for filtering, `regexp_extract()` is used for **extraction**. It allows you to search a string for a pattern and pull out a specific "capture group" (the part of the regex inside parentheses).

### Why use `regexp_extract()`?

* **Field Extraction:** Pull a Domain out of an Email address or a Process ID out of a Message string.
* **Cleaning Data:** Strip away prefixes or suffixes to normalize a value.
* **Complex Parsing:** Extract values from non-standard logs that haven't been fully normalized.

### Syntax

`regexp_extract(string, pattern, group_index)`

* **string:** The column or text you are searching.
* **pattern:** The RegEx with a capture group `()`.
* **group_index:** Which group to return (usually `1` for the first set of parentheses).

**Example: Extracting the Hostname from a Fully Qualified Domain Name (FQDN)** If you have a column `MachineName` with values like `rex.internal.example.net`, you can extract just the host:

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND host_only = regexp_extract(MachineName, '^([^.]+)', 1)
|> SELECT host_only, MachineName
```

---

## Security Detection Examples

### Failed Login Threshold

Detect users with more than 5 failed logins in the last hour.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> WHERE status = 'Failure'
|> AGGREGATE COUNT(*) AS failures GROUP BY actor.user.name, src_endpoint.ip
|> WHERE failures >= 5
|> ORDER BY failures DESC
```

| actor.user.name | src_endpoint.ip | failures |
| :---- | :---- | :---- |
| admin | 203.0.113.45 | 47 |
| jsmith | 198.51.100.23 | 12 |
| svc_backup | 10.0.1.105 | 8 |

### Account Enumeration

Detect IPs attempting to login as many different users.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> WHERE status = 'Failure'
|> AGGREGATE
    COUNT(*) AS attempts,
    COUNT(DISTINCT actor.user.name) AS unique_users
    GROUP BY src_endpoint.ip
|> WHERE unique_users >= 10
|> ORDER BY unique_users DESC
```

| src_endpoint.ip | attempts | unique_users |
| :---- | :---- | :---- |
| 203.0.113.45 | 847 | 156 |
| 198.51.100.88 | 234 | 45 |
| 192.0.2.17 | 89 | 12 |

### Brute Force Success

Detect successful logins that followed multiple failures.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> EXTEND
    prev_status = LAG(status) OVER (PARTITION BY actor.user.name ORDER BY time),
    prev_time = LAG(time) OVER (PARTITION BY actor.user.name ORDER BY time)
|> WHERE status = 'Success' AND prev_status = 'Failure'
|> EXTEND minutes_after_failure = TIMESTAMPDIFF(MINUTE, prev_time, time)
|> WHERE minutes_after_failure <= 5
|> SELECT time, actor.user.name, src_endpoint.ip, minutes_after_failure
```

### Off-Hours Activity

Detect logins outside business hours.

```sql
FROM lakewatch.gold.authentication
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 7 DAYS
|> WHERE status = 'Success'
|> EXTEND
    hour = HOUR(time),
    is_weekend = DAYOFWEEK(time) IN (1, 7)
|> WHERE hour < 6 OR hour >= 20 OR is_weekend = TRUE
|> SELECT time, actor.user.name, src_endpoint.ip, hour, is_weekend
```

### High-Volume Data Transfer

Detect unusual outbound data transfers.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> AGGREGATE SUM(traffic.bytes_out) AS total_bytes GROUP BY src_endpoint.ip, dst_endpoint.ip
|> WHERE total_bytes > 1000000000
|> ORDER BY total_bytes DESC
```

### Activity From a Watchlisted Subnet

Find connections to or from a watchlisted CIDR range. The `ip` mode of `SEARCH` matches addresses against the subnet directly, so no regular expression is needed.

```sql
FROM lakewatch.gold.network_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE SEARCH(src_endpoint.ip, dst_endpoint.ip, '203.0.113.0/24', mode => 'ip')
|> AGGREGATE
    COUNT(*) AS connections,
    SUM(traffic.bytes_out) AS bytes_out
    GROUP BY src_endpoint.ip, dst_endpoint.ip
|> ORDER BY connections DESC
```

### Suspicious Process Execution

Detect processes running from temporary directories.

```sql
FROM lakewatch.gold.process_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> WHERE
    process.file.path LIKE '%\\Temp\\%' OR
    process.file.path LIKE '%\\Downloads\\%' OR
    process.file.path LIKE '/tmp/%' OR
    process.file.path LIKE '/var/tmp/%'
|> SELECT time, device.hostname, actor.user.name, process.name, process.file.path
```

### Rare Process Detection

Find processes that have only run a few times.

```sql
FROM lakewatch.gold.process_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 7 DAYS
|> AGGREGATE
    COUNT(*) AS exec_count,
    COUNT(DISTINCT device.hostname) AS host_count,
    COLLECT_SET(device.hostname) AS hosts
    GROUP BY process.name
|> WHERE exec_count <= 3
|> ORDER BY exec_count
```

| process.name | exec_count | host_count | hosts |
| :---- | :---- | :---- | :---- |
| mimikatz.exe | 1 | 1 | ["WKS-042"] |
| nmap.exe | 2 | 1 | ["WKS-107"] |
| psexec.exe | 3 | 2 | ["SRV-DC01", "WKS-042"] |

### DNS Tunneling Indicator

Detect hosts making unusually high volumes of DNS queries.

```sql
FROM lakewatch.gold.dns_activity
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 1 HOUR
|> AGGREGATE
    COUNT(*) AS query_count,
    COUNT(DISTINCT query.hostname) AS unique_domains
    GROUP BY src_endpoint.ip
|> WHERE query_count >= 1000 OR unique_domains >= 500
|> ORDER BY query_count DESC
```

| src_endpoint.ip | query_count | unique_domains |
| :---- | :---- | :---- |
| 10.0.5.42 | 8472 | 8470 |
| 10.0.3.18 | 1247 | 89 |

### Threat Intelligence Match

Find connections to known malicious indicators.

```sql
FROM lakewatch.gold.network_activity AS n
|> WHERE time >= CURRENT_TIMESTAMP() - INTERVAL 24 HOURS
|> JOIN threat_intel AS t ON n.dst_endpoint.ip = t.indicator
|> WHERE t.confidence >= 80
|> SELECT
    n.time,
    n.src_endpoint.ip,
    n.dst_endpoint.ip,
    n.dst_endpoint.port,
    t.threat_type,
    t.threat_name,
    t.confidence
|> ORDER BY t.confidence DESC
```
