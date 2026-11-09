# Chakra Linter

## Purpose

- Measure how usable each Chakra execution trace (`.et` file) is before teams rely on it.
- Grade usability per consumer, because a trace serves some uses fully and others partially or not at all.
- Detect defects automatically, without manual inspection in a UI.
- Give engineers a suitability verdict per consumer with a specific reason for each gap.

## Problem Statement

- Teams share Chakra traces without a standard check of what each trace supports.
- Trace quality varies with the producer, the conversion pipeline, and the capture method.
- Defects surface late, often as misleading results in a downstream tool.
- Consumers have no fast way to determine whether a trace fits their purpose.
- Trace authors receive no structured feedback on what to correct.

## Goals

- Provide a quick, standalone linter for Chakra traces.
- Scan a set of traces and report how usable each one is per consumer.
- Detect structural, semantic, and completeness defects.
- Provide specific evidence that helps trace authors and consumers resolve gaps.
- Serve as a quality gate for tools that require well-formed traces, such as replay.

## Position in the Toolchain

- The linter runs last, on the converted `.et` files, before any consumer reads them.
- Pipeline: trace, link, convert, lint.

| Stage   | Tool                | Input                          | Output                    |
|---------|---------------------|--------------------------------|---------------------------|
| Trace   | PyTorch profilers   | Workload run                   | Host trace, device trace  |
| Link    | `chakra_trace_link` | Host trace, device trace       | Merged host-device JSON   |
| Convert | `chakra_converter`  | Merged host-device JSON        | Chakra `.et` files        |
| Lint    | `chakra_linter`     | `.et` files or directories     | Usability report          |

Example:

```bash
# 1. Trace: capture host and device traces per rank (PyTorch profilers)

# 2. Link: merge host and device traces
chakra_trace_link \
    --chakra-host-trace host_trace_0.json \
    --chakra-device-trace device_trace_0.json \
    --rank 0 \
    --output-file linked_0.json

# 3. Convert: encode the merged trace as protobuf
chakra_converter PyTorch --input linked_0.json --output traces/chakra.0.et

# 4. Lint: grade every trace in the directory per consumer
chakra_linter traces/ --report-output report.md
```

- Run the lint stage after every conversion to detect defects at the stage that introduced them.
- Use the report as a gate before replay, simulation, or analysis starts.
- Share the report with the trace so consumers see the supported uses.

## Methodology

- Usability is a degree, not a yes or no answer. Every trace receives integrity levels (tier 0), evidence levels per check group, and a usability level per consumer (tier 1).
- Tier 0 covers decode failure, empty traces, schema violations, and DAG validity. A tier 0 defect makes the trace unusable for every consumer.
- Evidence levels grade how complete each check group is. Each gap sets a level for its group; the worst level wins.
- Tier 1 gaps reduce usability for specific consumers and never invalidate a trace. Each gap lists the consumers it affects.
- Consumers:
  - **Replay:** re-executes operators; requires collective and point-to-point attributes, and replay units: the outermost CPU nodes (`is_cpu_op` true) that carry a non-empty `op_schema`, with I/O that fits it. Replay runs a unit with its whole subtree, so descendants are not graded. GPU kernels need no schema; replay runs the CPU operator that launches them. Durations may be zero, because replay runs the operator rather than modeling its time.
  - **Simulator:** models timing from the graph; requires communication attributes and a duration or I/O for each compute node.
  - **Analysis:** reads timing and structure; requires nonzero durations and a device link.
- Synthetic traces skip the timing and Kineto checks, so they favor simulator suitability. No separate flag applies.
- Example: a replay unit lacks `op_schema` but has a duration above zero. Replay cannot call it; simulator and analysis are `READY`.
- A replay unit with an `op_schema` and readable I/O that fits the schema is replayable, whatever its duration.

## Architecture

- One pass over the `.et` file feeds every rule family; no rule re-reads the file.
- Rule text and enabled state live in `rules.toml`; check logic lives in `*_rules.py`.
- Each module has one job:

| Module | Job |
|--------|-----|
| `linter.py` | Orchestrates the run: builds the families, collects hits, handles the CLI. |
| `*_rules.py` | One rule family each; fills accumulators and returns hits. |
| `index_builder.py` | Makes the single pass and holds the shared `TraceIndex`. |
| `consumer.py` | Grades gaps per consumer: evidence groups, gap levels, `TraceResult`; reads gap policy from `rules.toml`. |
| `messages.py` | Fills message templates from `rules.toml`. |
| `reports.py` | Renders markdown, HTML, stylish CLI, JSON, and SARIF output. |
| `rule_config.py` | Loads and validates `rules.toml` against the schema. |

- A hit carries a severity: `fatal` stops the scan; `error`, `warning`, and `info` show the message; `pass` shows nothing. For suitability, `info` counts as `pass`: it lowers no consumer impact.
- Orange blocks in the diagram mark the steps where a developer extends the rules.

### Module Interaction

- Participants are modules; arrows follow one lint run in order.
- Orange blocks mark where a developer extends the rules.

```mermaid
sequenceDiagram
    autonumber
    participant CLI as linter.py<br/>main, scan_trace
    participant CFG as rule_config.py<br/>rules.toml + schema
    participant FAM as *_rules.py<br/>RuleFamily subclasses
    participant IDX as index_builder.py<br/>IndexBuilder, TraceIndex
    participant POL as consumer.py, messages.py<br/>gap policy, render

    CLI->>CFG: load_rules()
    CFG-->>CLI: rules, message templates

    rect rgb(255, 224, 178)
    Note over CFG: EXTEND 1: add a [[rule]] entry in rules.toml<br/>and any new placeholder in rules.schema.json
    end

    CLI->>FAM: instantiate families (disabled IDs)
    FAM->>CFG: shipped_rules() checks every @rule ID exists

    rect rgb(255, 224, 178)
    Note over FAM: EXTEND 2: add an @rule("ID") method to a family,<br/>or a new @register RuleFamily subclass,<br/>then list it in scan_trace
    end

    CLI->>IDX: IndexBuilder(path, families).build()

    loop once per node (the only read of the file)
        IDX->>IDX: decode node, fill TraceIndex facts
        IDX->>FAM: add(node, attrs)
        Note over FAM: update counters and samples only,<br/>never retain node or attrs
    end

    rect rgb(255, 224, 178)
    Note over IDX: EXTEND 3: a fact several families need<br/>becomes a TraceIndex field filled here
    end

    IDX-->>CLI: TraceIndex

    loop each family
        CLI->>FAM: finish(index)
        Note over FAM: run enabled @rule checks,<br/>resolve cross-node checks here
        FAM-->>CLI: list of Hit
    end

    CLI->>POL: render message, gap_for (Hit)
    POL->>CFG: message template by rule ID

    rect rgb(255, 224, 178)
    Note over POL: EXTEND 4: add a consumer_impact line to the rule<br/>entry in rules.toml; add `group`, `level` and `remediation` (or a shared `[[remediation]]` entry) in the same file
    end

    POL-->>CLI: Gap, Issue
    CLI->>CLI: TraceResult, then render reports
```

### Where to Extend

| Change                | Files to touch                                                                             |
|-----------------------|--------------------------------------------------------------------------------------------|
| Reword or toggle rule | `rules.toml`                                                                               |
| New placeholder       | `x-placeholders` in `rules.schema.json`, before use in a message                           |
| New rule, existing family | `rules.toml` entry, `@rule("ID")` method in `*_rules.py`, a `consumer_impact` line, `group`, `level` and remediation on the rule entry |
| New family            | New `*_rules.py` with `@register` subclass, instance and `finish` call in `scan_trace`     |
| New shared fact       | Field on `TraceIndex`, filled in `IndexBuilder`; never a per-family node copy              |

- `add` runs once per node; keep only counters, samples, and scalars.
- `finish` runs once after the pass; resolve cross-node checks there.
- A family never retains `node` or `attrs`.

## Rule Configuration (`rules.toml`)

- `rules.toml` declares every check the linter runs: ID, name, description, enabled state, and report message.
- `rules.schema.json` defines the syntax of that file.
- The `*_rules.py` families implement the check logic that each rule ID selects.
- The three files form one contract. No file is complete without the other two.

### Schema

- One `[[rule]]` table per check. The file requires at least one rule.
- Unknown keys are rejected.

| Key           | Type            | Required | Constraint                                                          |
|---------------|-----------------|----------|---------------------------------------------------------------------|
| `id`          | string          | Yes      | Two or three capital letters plus three digits, such as `DAG005`.   |
| `name`        | string          | Yes      | Kebab-case label, such as `dag-cycle`.                              |
| `description` | string          | Yes      | What the rule checks and why it matters. Ends with a period.        |
| `enabled`     | boolean         | Yes      | `true` runs the rule; `false` drops its findings before grading.    |
| `severity`    | string          | Yes      | `fatal`, `error`, `warning`, `info`, or `pass`. One fixed value; a case that differs is a separate rule. |
| `message`     | string          | Yes      | Report text. `{placeholders}` name values that the check supplies.  |
| `consumer`    | inline table    | Yes      | `{ replay = x, simulator = y, analysis = z }`; each value is `READY` (no known gap), `LIMITED` (known gap lowers fidelity), `REVIEW` (linter cannot decide; manual inspection) or `NOT SUITABLE` (consumer cannot use the trace). Applies when a finding reports at `warning` or above; `info` and `pass` rules use `READY`. |
| `exempt`      | array of string | No       | Shell-style name patterns exempt from the check. `OPS001` only.     |

Example:

```toml
[[rule]]
id = "DAG003"
name = "dag-self-dep"
description = "A node lists its own ID as a dependency. The node can never become ready, so replay and simulation stall."
enabled = true
severity = "error"
message = "self-dependency"
```

- The ID prefix groups rules by area: `INT`, `DAG`, `TIM`, `KIN`, `COM`, `OPS`, `IO`, `MET`, `ATT`.
- IDs stay stable and are never reused for a different rule.
- Placeholders are limited per rule. The loader rejects a message that names a value its check does not supply.

### Source of Truth

- `rules.toml` owns the rule catalog: which rules exist, their wording, and their default state.
- Rule family modules (`*_rules.py`) own detection: each family class fills accumulators during the single pass over the trace, and its `@rule("ID")` methods turn them into findings.
- `rules.toml` also holds one suitability entry per consumer (`SUI001` to `SUI003`): its ID, name and text.
- Each rule sets its consumer impact on its own `consumer_impact` line, for example `consumer_impact = { replay = "REVIEW", analysis = "REVIEW" }`. The line applies when a finding of the rule reports at `fatal`, `error` or `warning`.
- Each rule sets its evidence `group` and `level` in `rules.toml`; an integrity rule sets `check` instead.
- Remediation lives in `rules.toml`: a shared `[[remediation]]` entry per check or (group, level), plus an optional `remediation` on a rule that overrides it. A gap rule without a resolvable remediation fails at load.
- `rules.toml` holds the one severity and the one `consumer_impact` of each rule. A check never overrides either. A case that differs is a separate rule, such as `OPS001` (some operators lack `op_schema`) and `OPS005` (all lack it).
- A rule requires both halves. A TOML entry without a check never fires; a check without an entry fails at startup.
- `x-placeholders` in `rules.schema.json` is the master list of placeholder names, each with a description.
- Any rule may use any master name; a check that does not supply a name it is given fails at render.
- The loader falls back to the shipped file for any rule that a custom file omits.

| Concern                   | Defined in                      |
|---------------------------|---------------------------------|
| Rule ID, name, wording    | `rules.toml`                    |
| Enabled by default        | `rules.toml`                    |
| Exempt annotation names   | `rules.toml` (`OPS001`)         |
| File syntax               | `rules.schema.json`             |
| Detection logic           | `*_rules.py` (one family per category) |
| Placeholder names, meaning | `rules.schema.json` (`x-placeholders`) |
| Consumer impact per gap   | `rules.toml` (`consumer_impact` on each `[[rule]]`) |
| Evidence group and level  | `rules.toml` (`group`, `level` on each `[[rule]]`) |
| Integrity check           | `rules.toml` (`check` on each `[[rule]]`) |
| Remediation               | `rules.toml` (`[[remediation]]`, rule `remediation`) |

### Validation

- The loader fails fast, before any trace scan, on a missing, malformed, or invalid rule file.
- Checks at load time:
  - TOML syntax.
  - Conformance to `rules.schema.json`.
  - Unique rule IDs and names.
  - Valid message placeholders.
  - `INT001` and `INT002` stay enabled, because an unreadable or empty trace cannot be graded.
- `tests/linter/test_rules_toml.py` enforces the criteria that the schema cannot express:
  - IDs and names are unique.
  - Prefix groups are contiguous and numbered from 001.
  - Placeholders match what each check supplies.
  - `exempt` belongs to one rule only.
  - A committed ID keeps its name, or retires.
- `tests/linter/test_rule_inventory.py` confirms that the rule file and the code agree.

### Usage

- `--rules FILE` loads a custom rule file in place of the shipped one.
- `--list-rules` prints every rule with its enabled state, then exits.
- `--enable-rule` and `--disable-rule` override the file for one run. Each accepts a rule ID, name, or prefix, such as `DAG`, and repeats.
- Example: disable `KIN001` for a genuine CPU-only capture.

```bash
chakra_linter traces/ --disable-rule KIN001
```

### Changing a Rule

- Edit wording, remediation, group, level, default state, or `exempt` patterns in `rules.toml` alone. No code change applies.
- Add a rule by adding a `[[rule]]` entry, a `@rule("ID")` method on its family in `*_rules.py`, and a `consumer_impact` line, `group`, `level` and remediation on the rule entry in `rules.toml`. Add any new placeholder to `x-placeholders` first.
- Add a family by subclassing `RuleFamily`, decorating it with `@register`, and listing it in `scan_trace`.
- Set `severity` on the new `[[rule]]` entry. Override it on the hit only when the level varies with the data.
- Retire a rule by leaving its ID unused. Do not reassign the ID.
- Run the linter tests after every change to the file.
