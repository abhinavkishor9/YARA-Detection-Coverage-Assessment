# Timeline – YARA Detection Coverage Assessment

**Date:** 25 November 2026  
**Environment:** Ubuntu 24.04 on WSL  
**YARA version:** 4.5.0

| Stage | Activity | Evidence / Outcome |
|---|---|---|
| 1 | Created Lab 32 workspace | `rules/`, `samples/positive/`, `samples/negative/`, `results/` and `reports/` directories created |
| 2 | Checked YARA environment | YARA CLI 4.5.0 available |
| 3 | Checked Python YARA module | Python module unavailable; CLI retained as assessment interface |
| 4 | Discovered existing rules | 16 `.yar` files identified across Labs 02, 03, 14, 21, 22, 24, 25 and 27 |
| 5 | Inspected rule definitions | Strings, byte patterns and conditions reviewed |
| 6 | Collected rules | 16 rule files copied into Lab 32 `rules/` |
| 7 | Created rule inventory | `reports/rule-inventory.txt` populated with 16 rules |
| 8 | Prepared initial test corpus | Three positive-labelled and two negative-labelled text samples created |
| 9 | Attempted directory-based rule loading | `yara -r rules/ samples/positive/` failed because the rule source was supplied as a directory |
| 10 | Consolidated rules | `results/all-rules.yar` created |
| 11 | Checked rule count | 16 rule declarations confirmed |
| 12 | Validated syntax | Consolidated ruleset accepted by YARA without a reported syntax error |
| 13 | Scanned positive-labelled samples | No matches recorded |
| 14 | Scanned negative-labelled samples | No matches recorded |
| 15 | Reviewed empty positive output | Sample contents did not satisfy the full conditions of the relevant rules; API sample was outside current rule coverage |
| 16 | Created evidence hashes | SHA-256 hashes saved in `results/sample-and-rule-hashes.txt` |
| 17 | Prepared assessment reports | Detection matrix and findings report initialized; classifications remain pending |

## Final Status

### Completed

- Workspace preparation
- Rule discovery and collection
- Inspection of 16 rule definitions
- Rule inventory
- Rule consolidation
- Syntax validation
- Initial sample creation and scanning
- SHA-256 evidence recording

### Pending

- Rule-specific positive and negative test fixtures
- Expected-result definitions for each rule/sample pair
- Detection matrix population
- TP, FP, FN and TN calculations
- Rule overlap validation through actual scan results
- Detection gap assessment
- Final coverage conclusions

## Timeline Conclusion

The work completed on 25 November established a validated consolidated ruleset and an initial assessment structure.

The initial scan results exposed a test-design issue: the positive-labelled samples did not contain all indicators required by their intended rules.

The next stage is to improve the controlled corpus and evaluate each rule against its actual detection objective.
