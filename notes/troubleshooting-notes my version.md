# Troubleshooting Notes 
## 1. Python YARA Module Not Installed

### Issue

The following command was executed:

```bash
python3 -c "import yara; print(yara.__version__)"
```

It returned:

```text
ModuleNotFoundError: No module named 'yara'
```

### Investigation

The YARA command-line utility was available:

```bash
which yara
```

Output:

```text
/usr/bin/yara
```

Version check:

```bash
yara --version
```

Output:

```text
4.5.0
```

### Resolution

The assessment continued using the YARA CLI.

The Python binding was not required for the current workflow, so no additional installation was performed.

**Lesson:** The Python YARA module and the YARA command-line utility are separate interfaces. The absence of the Python module does not mean the CLI is unavailable.

---

## 2. Inventory File Creation Failed

### Issue

The inventory file was initially created while the shell was in:

```text
~/malware-yara-labs
```

The command:

```bash
cat > reports/rule-inventory.txt
```

returned:

```text
-bash: reports/rule-inventory.txt: No such file or directory
```

### Cause

The `reports/` directory existed inside `lab32`, not directly under `malware-yara-labs`.

### Resolution

The working directory was corrected:

```bash
cd ~/malware-yara-labs/lab32
```

The path was verified:

```bash
pwd
```

Output:

```text
/home/abhinav/malware-yara-labs/lab32
```

The inventory file was then created successfully.

**Lesson:** Relative paths are resolved from the current working directory. Verify `pwd` before creating files in a lab workspace.

---

## 3. YARA Could Not Load a Rule Directory

### Issue

The following command was attempted:

```bash
yara -r rules/ samples/positive/
```

Output:

```text
rules/(1): error: input in flex scanner failed
```

### Cause

The first positional argument to YARA must identify a rule source, not a directory containing multiple rule files.

The `-r` option enables recursive scanning of target files. It does not enable recursive loading of rule files from a directory.

### Resolution

The individual rule files were consolidated:

```bash
cat rules/*.yar > results/all-rules.yar
```

The consolidated ruleset was then used:

```bash
yara results/all-rules.yar /dev/null
```

For recursive scanning of target samples:

```bash
yara -r results/all-rules.yar samples/positive/
```

**Lesson:** Distinguish between the rule source and the target directory in YARA CLI syntax.

---

## 4. Initial Positive Scan Produced No Matches

### Observation

The positive scan command completed without producing matches:

```bash
yara -r results/all-rules.yar samples/positive/ \
  | tee results/positive-results.txt
```

The output file was empty.

### Investigation

The sample contents were compared with the actual rule conditions.

#### Downloader sample

The sample contained:

- `DownloadString`
- `DownloadFile`
- `Invoke-WebRequest`
- `http://example.invalid/payload`

The downloader rules require `WriteFile`, `CreateProcess` and HTTPS URL conditions. The Lab 27 rule additionally requires the exact URL `https://example.invalid/payload.bin`.

The sample did not meet those conditions.

#### Persistence sample

The sample contained:

- `Software\Microsoft\Windows\CurrentVersion\Run`
- `schtasks.exe`
- `CurrentVersion\Run`

The rules require scheduled-task strings such as `New-ScheduledTaskAction` and `Register-ScheduledTask`. The Lab 27 rule also requires the full HKCU registry path and `Startup`.

The sample did not meet the complete conditions.

#### API sample

The sample contained:

- `VirtualAlloc`
- `WriteProcessMemory`
- `CreateRemoteThread`

None of the inspected rules searches for this combination.

### Resolution

The initial positive samples must be replaced or supplemented with test fixtures designed around the exact conditions of the rules.

**Lesson:** A file placed in a positive directory is not automatically a valid positive test. Its contents must satisfy the rule being evaluated.

---

## 5. Empty Negative Scan Output

### Observation

The negative scan was executed:

```bash
yara -r results/all-rules.yar samples/negative/ \
  | tee results/negative-results.txt
```

The output file was empty.

### Interpretation

The two benign-labelled samples did not match the current ruleset.

This is an observed result for the two supplied files only.

It does not establish a low false-positive rate because the negative corpus is very small and does not represent the range of benign files encountered in real environments.

### Recommended action

Expand the negative test corpus with carefully selected benign fixtures that contain individual keywords or partial indicators without satisfying the complete rule conditions.

---

## 6. Detection Matrix Contains Only a Header

### Observation

The file:

```text
reports/detection-matrix.csv
```

was created with the following header:

```csv
Rule,Sample,Expected_Result,Actual_Result,Classification,Remarks
```

No test rows were added.

### Interpretation

No TP, FP, FN or TN classifications have been established.

### Recommended action

Populate the matrix only after defining expected results for each rule/sample pair and executing the corresponding tests.

Do not infer expected results solely from whether a sample is stored in the positive or negative directory.

---

