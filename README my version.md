# YARA-Detection-Coverage-Assessment
## Overview
### 1. What Is YARA?

YARA is a pattern-matching tool used to identify files based on characteristics such as:

- Text strings
- Hexadecimal byte sequences
- File-format indicators
- Combinations of multiple conditions
- Case-sensitive or case-insensitive patterns

A YARA rule defines the indicators to search for and the conditions under which a match should be reported.

A rule match means that the specified conditions were satisfied. It does not independently establish that a file is malicious.

### 2. What Is Detection Coverage?

Detection coverage assessment evaluates whether a collection of rules identifies the indicators and patterns it was designed to detect.

The assessment considers:

- Whether each rule compiles
- Whether its conditions reflect its stated objective
- Whether expected test samples trigger it
- Whether unrelated samples trigger it
- Whether multiple rules identify the same patterns
- Whether the ruleset contains identifiable coverage gaps

A large number of rules does not automatically mean strong detection coverage.

### 3. Rule Compilation and Detection Validation

These are two different activities.

#### Rule compilation

Compilation checks whether the rule syntax is accepted by YARA.

For example:

```bash
yara results/all-rules.yar /dev/null
```

A successful command confirms that YARA accepts the consolidated rule source.

#### Detection validation

Detection validation checks whether the rule matches the expected test samples.

A rule can compile successfully but still fail to identify its intended sample because:

- Its condition is too restrictive.
- The sample does not contain the required indicators.
- The rule uses an exact string that differs from the sample.
- The expected pattern is not present.
- The rule does not cover the behavior being tested.

Therefore, compilation alone is not evidence of detection effectiveness.

### 4. Test Corpus

A test corpus is a collection of files used to evaluate detection rules.

#### Positive test samples

A positive test sample contains the indicators expected to trigger a particular rule.

For example, a downloader-rule test fixture must contain all strings required by that rule's condition.

#### Negative test samples

A negative test sample is expected not to trigger the rule being evaluated.

Negative samples should be selected carefully. A file containing one broad keyword may be expected to match a broad keyword rule even if it is otherwise benign.

#### Expected results

Expected outcomes should be defined before scanning.

The assessment must consider each rule/sample pair rather than assuming that every file in a positive directory should trigger every rule.

### 5. Detection Classification

Four classifications are used to evaluate rule outcomes.

| Classification | Meaning |
|---|---|
| True Positive (TP) | Rule matches a sample expected to match |
| False Positive (FP) | Rule matches a sample expected not to match |
| False Negative (FN) | Rule fails to match a sample expected to match |
| True Negative (TN) | Rule correctly does not match a sample expected not to match |

These classifications require a clearly defined expected result for each test.

### 6. Detection Metrics

#### Positive detection rate

Measures the proportion of expected positive test cases detected by the rule.

\[
\text{Positive Detection Rate}
=
\frac{TP}{TP+FN}\times100
\]

#### False-positive rate

Measures the proportion of expected negative test cases incorrectly matched.

\[
\text{False Positive Rate}
=
\frac{FP}{FP+TN}\times100
\]

These metrics are meaningful only when the test corpus contains suitable positive and negative cases.

A metric calculated from a small synthetic corpus must not be presented as real-world detection performance.

### 7. Rule Overlap

Rule overlap occurs when multiple rules match the same sample or use the same indicators.

Examples from this assessment include:

- Two rules using the same exact hexadecimal byte sequence.
- Two rules sharing a wildcard byte pattern.
- Multiple UPX rules containing the same marker.
- Downloader and persistence rules using related indicators with different conditions.

Overlap is not automatically a problem.

It may provide complementary detection coverage, or it may indicate duplicate logic that should be reviewed.

Actual overlap must be confirmed through controlled test results.

### 8. Broad and Specific Conditions

A broad rule may match a common keyword without requiring additional context.

A specific rule may require multiple indicators or an exact command string.

Broad conditions can increase the number of matches, including matches on benign files.

More restrictive conditions can reduce unintended matches but may miss samples that use different strings or variations.

The objective is to understand the trade-off and validate the rule against its intended use.

### 9. Detection Gaps

A detection gap exists when the ruleset does not identify an indicator or test case within its defined assessment scope.

Potential causes include:

- Missing rules for a relevant indicator.
- Incomplete string coverage.
- Overly restrictive conditions.
- Unsupported file formats or representations.
- Variations in strings or byte patterns.
- Test cases that were not included in the corpus.

A gap must be demonstrated against a defined detection objective. The absence of a match alone is not sufficient.

### 10. Regression Testing

Regression testing checks whether existing detection behavior remains consistent after rule changes.

For example, an exact byte-pattern rule from one lab and a later regression rule may use the same sequence.

A controlled test can determine whether both rules continue to match the same fixture after future changes.

### 11. Evidence Integrity

SHA-256 hashes can be generated for rules and test samples:

```bash
sha256sum rules/*.yar samples/positive/* samples/negative/*
```

Hashes help identify changes to the files used during an assessment.

They do not establish whether a sample is malicious or benign.

### 12. Key Principle

YARA detection assessment is not about maximizing the number of matches.

It is about determining whether each rule behaves as intended, whether its conditions are appropriate, and whether its results are supported by controlled test evidence.

**A match is an indicator to investigate, not a malware verdict.**


This lab evaluates the detection coverage of 16 existing YARA rules developed across previous malware analysis and detection exercises.

Rather than creating another set of detection rules, the objective is to assess the rules already available:

- Do the rules compile successfully?
- Do their conditions match their intended detection objectives?
- Do multiple rules detect the same indicators?
- Are the test samples suitable for validating each rule?
- Can broad matching conditions produce unintended detections?
- Which detection gaps remain?

The assessment uses a controlled corpus of synthetic text and byte-pattern samples. A YARA match is treated as evidence that a rule condition matched, not as proof that a file is malicious.

## Lab Objectives

### Primary Objective

Evaluate the quality and intended behavior of an existing YARA ruleset by examining its conditions, testing it against controlled samples and documenting areas of overlap and potential detection gaps.

### Learning Objectives

By completing this lab, the learner should be able to:

1. **Inventory existing YARA rules**

   Identify rule files from multiple exercises and organize them into a centralized assessment workspace.

2. **Interpret rule conditions**

   Examine strings, hexadecimal patterns, modifiers and logical conditions to understand exactly what each rule detects.

3. **Validate rule compilation**

   Consolidate multiple rule files and verify that the combined ruleset is accepted by the YARA CLI.

4. **Design controlled test samples**

   Prepare synthetic samples that contain the complete indicators required by individual rules.

5. **Define expected outcomes**

   Document whether each rule should match or not match a particular test sample before executing the scan.

6. **Evaluate detection behavior**

   Compare actual YARA output against expected results and identify successful matches and missed detections.

7. **Understand false-positive behavior**

   Examine whether broad keywords or less restrictive conditions produce matches on samples not expected to trigger a rule.

8. **Identify rule overlap**

   Compare rules that share strings, byte patterns or detection objectives and determine whether their behavior is complementary or duplicated.

9. **Assess detection gaps**

   Identify test cases that fall outside the coverage of the existing ruleset and distinguish genuine gaps from incorrectly designed test samples.

10. **Preserve investigation evidence**

    Record rule inventories, validation output, scan results and SHA-256 hashes to support reproducibility.

### Expected Learning Outcome

The learner should be able to explain why successful rule compilation does not guarantee detection effectiveness, construct a meaningful test matrix, interpret YARA matches carefully and support coverage conclusions with evidence.

The assessment should distinguish confirmed findings from untested assumptions and avoid treating synthetic rule matches as proof of malicious activity.

## Lab Scenario

### Scenario

A security team has accumulated YARA rules through multiple malware analysis and detection exercises. These rules were created at different stages to identify suspicious strings, file-format indicators, downloader-related patterns, persistence references and custom byte sequences.

Although the rules were developed and tested individually, the team has not performed a consolidated assessment of their detection coverage.

The team wants to understand whether the existing rules behave as intended when evaluated together.

The assessment begins by collecting 16 rules from previous labs and placing them in a centralized workspace. The rules are inspected, documented and combined into a single ruleset.

The consolidated ruleset passes syntax validation. However, successful compilation does not answer the team's main question: do the rules actually detect the patterns they were designed to identify?

### Initial Testing

A small controlled corpus is prepared with positive-labelled and negative-labelled samples.

The initial scan produces no matches in either directory.

Instead of immediately concluding that the rules are ineffective, the analyst reviews the actual rule conditions and compares them with the sample contents.

The review reveals that the downloader and persistence samples do not contain all the required indicators. The API sample contains function names that are not covered by the inspected rules.

The initial test corpus therefore cannot support a reliable assessment of detection coverage.

### Investigation Requirements

The analyst must:

- Review each rule's strings, byte patterns and logical conditions.
- Identify the exact indicators required for a match.
- Create rule-specific positive and negative test fixtures.
- Define expected outcomes before executing scans.
- Compare actual results with expected results.
- Examine shared indicators and possible rule overlap.
- Identify potential detection gaps within the defined scope.
- Preserve the results and supporting evidence.

### Expected Investigation Approach

The analyst should avoid treating a sample's folder placement as proof of its expected detection outcome.

A positive-labelled sample must contain the complete indicators required by the rule being tested. A negative test must be selected according to the expected behavior of that particular rule.

For example, a broad PowerShell keyword rule may legitimately match a benign document containing the word `PowerShell`. That match must be interpreted against the rule's objective rather than automatically labelled malicious.

Similarly, two rules sharing a byte pattern may both match the same controlled fixture. This is evidence of overlapping detection behavior, but further analysis is needed to decide whether the overlap is useful or redundant.

### Final Deliverables

The assessment should produce:

1. A centralized inventory of all selected rules.
2. A consolidated ruleset with successful syntax validation.
3. A controlled test corpus with documented expected outcomes.
4. A detection matrix containing actual results and classifications.
5. An analysis of rule overlap and potential false positives.
6. A record of detection gaps and proposed improvements.
7. SHA-256 hashes and supporting investigation evidence.

### Scenario Outcome

The initial stage of the assessment confirms that the 16 collected rules compile successfully.

The first test run also demonstrates why test-case design matters: samples that do not contain the complete required indicators cannot reliably validate a rule.

The investigation remains open until suitable test fixtures are prepared, expected outcomes are documented and the rules are evaluated against them.

The objective is not to make every rule produce a match. It is to establish whether each rule provides the detection behavior its conditions and stated purpose require.

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

