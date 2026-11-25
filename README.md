# YARA Detection Coverage Assessment
## Overview

This lab evaluates the detection coverage of 16 existing YARA rules developed across previous malware analysis and detection exercises.

Rather than creating another set of detection rules, the objective is to assess the rules already available:

- Do the rules compile successfully?
- Do their conditions match their intended detection objectives?
- Do multiple rules detect the same indicators?
- Are the test samples suitable for validating each rule?
- Can broad matching conditions produce unintended detections?
- Which detection gaps remain?

The assessment uses a controlled corpus of synthetic text and byte-pattern samples. A YARA match is treated as evidence that a rule condition matched, not as proof that a file is malicious.

## Lab Environment

| Component | Details |
|---|---|
| Operating environment | Ubuntu 24.04 on WSL |
| YARA CLI | 4.5.0 |
| Rule language | YARA |
| Workspace | `~/malware-yara-labs/lab32` |
| Python YARA module | Not installed; CLI workflow used |

## Assessment Scope

The assessment consolidates 16 rules originating from:

| Source Lab | Number of Rules |
|---|---:|
| Lab 02 | 1 |
| Lab 03 | 4 |
| Lab 14 | 3 |
| Lab 21 | 1 |
| Lab 22 | 1 |
| Lab 24 | 2 |
| Lab 25 | 1 |
| Lab 27 | 3 |
| **Total** | **16** |

The rules cover:

- Exact and case-insensitive string matching
- Broad keyword matching
- Combined string conditions
- ELF file identification
- UPX indicators
- Simulated downloader behavior
- Simulated Windows persistence indicators
- Exact and wildcard byte patterns
- Synthetic sample-family identification
- Regression testing

## Investigation Workflow

### 1. Rule discovery and selection

Existing `.yar` files were identified across Labs 02, 03, 14, 21, 22, 24, 25 and 27.

The rules were copied into the Lab 32 `rules/` directory for centralized assessment.

### 2. Rule inventory

A rule inventory was created to record:

- Rule name
- Source lab
- Detection objective
- Assessment focus

The inventory contains 16 rule declarations.

### 3. Rule consolidation

The individual rule files were combined into:

```text
results/all-rules.yar
```

The consolidated file contained 16 rule declarations.

### 4. Syntax validation

The consolidated rule file was tested using:

```bash
yara results/all-rules.yar /dev/null
```

The command returned without a syntax error.

### 5. Initial sample preparation

Three positive-labelled samples and two negative-labelled samples were created.

The initial positive samples represented downloader-related strings, persistence-related strings and API names. The negative samples contained general documentation and configuration text.

### 6. Initial scanning

The consolidated rules were executed against both sample directories.

The positive and negative result files were created, but both were empty.

This was an important assessment finding: the existing positive-labelled samples did not establish successful rule detection. Their contents did not satisfy the complete conditions of the relevant rules.

## Confirmed Findings

### Rule validation

- 16 individual YARA rule files were collected.
- 16 rule declarations were found in the consolidated file.
- The consolidated file passed the YARA CLI syntax check.
- Individual rule files were also checked without reported compilation errors.

### Rule overlap observations

The inspected rule definitions revealed several areas requiring comparison:

1. `Lab24_Exact_Custom_Byte_Pattern` and `Custom_Byte_Pattern_Regression` use the same exact byte sequence.
2. `Lab24_Wildcard_Custom_Byte_Pattern` and `Lab25_Related_Sample_Family` use the same wildcard byte pattern, although the Lab 25 rule additionally requires a family marker.
3. The Lab 14 UPX marker rule and multi-indicator rule both include the `UPX!` string.
4. The Lab 21 and Lab 27 downloader rules use different URL conditions and matching behavior.
5. The Lab 22 and Lab 27 persistence rules use different combinations of registry and scheduled-task indicators.

These are rule-definition overlaps or similarities. Their actual match overlap still requires controlled testing.

### Initial scan results

| Scan | Result |
|---|---|
| Positive-labelled samples | No matches recorded |
| Negative-labelled samples | No matches recorded |

The absence of matches does not establish that all rules have false negatives or that all negative samples are true negatives. The test corpus is not yet adequate to support those classifications.

## Important Assessment Limitations

- The downloader test sample did not contain the complete set of strings required by the downloader rules.
- The persistence test sample did not contain all the scheduled-task and registry indicators required by the persistence rules.
- The API test sample contained `VirtualAlloc`, `WriteProcessMemory` and `CreateRemoteThread`, but none of the inspected rules specifically searches for those strings.
- The current negative samples are limited examples, not a representative benign corpus.
- No detection metrics have been calculated.
- No real malware samples were used in this assessment.

## Detection Metrics

The assessment will use the following definitions once suitable test cases and expected outcomes are established:

| Metric | Meaning |
|---|---|
| True Positive (TP) | A rule matches a sample expected to match that rule |
| False Positive (FP) | A rule matches a sample expected not to match that rule |
| False Negative (FN) | A rule fails to match a sample expected to match that rule |
| True Negative (TN) | A rule correctly does not match a sample expected not to match that rule |

Positive detection rate:

`TP / (TP + FN) × 100`

False-positive rate:

`FP / (FP + TN) × 100`

These metrics will describe only the controlled test corpus, not real-world detection performance.

## Evidence and Reports

| File | Purpose |
|---|---|
| `reports/rule-inventory.txt` | Inventory of the 16 selected rules |
| `reports/rule-validation.txt` | Consolidation and syntax-validation record |
| `reports/detection-matrix.csv` | Template for expected and actual rule outcomes |
| `reports/findings.md` | Assessment findings record |
| `results/all-rules.yar` | Consolidated ruleset |
| `results/positive-results.txt` | Initial positive-directory scan output |
| `results/negative-results.txt` | Initial negative-directory scan output |
| `results/sample-and-rule-hashes.txt` | SHA-256 hashes of collected rules and samples |

The detection matrix currently contains only its header. The findings report was initialized with pending sections. These files must be updated after the controlled test cases are validated.

## Key Learning

A syntactically valid YARA rule is not necessarily an effective detection rule.

Coverage assessment requires more than compiling rules or counting matches. Each rule must be tested against samples designed around its actual conditions, with expected outcomes documented before interpreting the results.

A match is an indicator to investigate, not a malware verdict.
