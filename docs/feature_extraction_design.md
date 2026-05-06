# Static Feature Extraction Design — npm & PyPI

This document defines a production-ready static feature extraction pipeline that combines AST-based analysis (primary signal), Shannon entropy (contextual signal), and package metadata analysis (ecosystem-specific). The output is a flat feature dictionary suitable for LightGBM/XGBoost.

## Goals
- Exhaustively capture static indicators of malicious behavior in npm and PyPI packages.
- Attach entropy measurements to AST contexts (not standalone).
- Produce derived behavioral features that represent intent (e.g., exfiltration, obfuscated execution).
- Be implementation-ready: precise extraction logic, types, examples, traversal guidance, thresholds.

## Summary of approach
- Parse package archive or directory safely (existing `SafeExtractor`) and enumerate files.
- For each file: read bytes, compute Shannon entropy (fast vectorized implementation), record per-literal and per-identifier entropy where applicable.
- For code files (.js, .mjs, .cjs, .py): parse AST (esprima for JS, ast for Python). Walk AST tracking context stack and attaching entropy values to nodes (string literals, identifiers).
- Extract package metadata (package.json, pyproject.toml, setup.py) and derive install-time and naming signals.
- Compute derived behavioral features by correlating AST events and entropy signals.
- Emit a flat dict for each package.

## Entropy: definitions and thresholds
- **Entropy computation**:
	- Use the Shannon entropy in bits/byte computed over the byte sequence of the string literal or identifier UTF-8 bytes.
	- For raw files, compute entropy over file bytes (existing `calculate_shannon_entropy`). For strings/identifiers, convert to UTF-8 bytes and compute the same function.
	- Normalize identifiers and short strings: only measure entropy when length >= 8 characters; for shorter strings compute but mark with `short_string` flag.
- **Thresholds (recommended defaults — tune per corpus)**:
	- `low_entropy`: < 3.0 bits/byte
	- `medium_entropy`: 3.0 — 4.5 bits/byte
	- `high_entropy`: >= 4.5 bits/byte
	- `very_high_entropy`: >= 6.0 bits/byte (strongly indicates compressed/encoded/binary data)
- **Linkage to AST nodes**:
	- When visiting a string literal or identifier node, compute entropy and attach to the visited node context record: `{node_id, type, entropy, length, parent_construct}`.
	- Parent constructs include CallExpression (callee name, sink type), Assignment, Import/Require argument, Function arg, Exec/eval argument, Request URL literal, Child process command, Setup script body.

### How entropy is NOT standalone
Do not include raw `file_entropy` as an isolated indicator. Instead produce features that combine entropy with AST usage context, e.g. `high_entropy_literal_in_eval_count`.

## Feature categories and exhaustive feature list
For each feature: Feature name, Type, Extraction logic, Trigger example.

> NOTE: All features must appear in final flat schema even if zero.

### A. Code execution & dynamic evaluation

- `eval_count` (int): count of direct `eval(...)` calls in JS and `eval(...)` in Python.
	- Logic: AST CallExpression where callee is Identifier `eval`.
	- Example: `eval(payload)`

- `high_entropy_eval_count` (int): number of `eval` invocations whose string argument entropy >= 4.5.
	- Logic: when CallExpression `eval` and first arg is a string literal, compute entropy and increment if above threshold.
	- Example: `eval('ZG9zb21l...')` (base64-like)

- `exec_shell_eval_count` (int): number of dynamic execution patterns that combine string construction + eval/exec (concatenation/template + eval).
	- Logic: detect binary/concat/template nodes used as `eval` argument; also detect ES `new Function(...)` or Python `compile(..., 'exec')` patterns.
	- Example: `new Function('a','b', code)` or `exec(compile(payload, '<string>', 'exec'))`

- `new_function_count` (int): JS `new Function(...)` occurrences.

- `exec_count` (int): Python `exec(...)` call occurrences.

### B. Process & system control

- `child_process_spawn_count` (int): JS `child_process.spawn`/`exec`/`execSync` uses; dynamic require('child_process') detection.
	- Logic: require/import of `child_process` OR MemberExpression with `child_process` callee in JS; Python `subprocess` usage via import or `subprocess.Popen`/`run` calls.
	- Example JS: `require('child_process').exec('cmd')` ; Python: `subprocess.call(['cmd'])`

- `install_time_exec_count` (int): package-level or install-script code that invokes child process or exec during install scripts (from package.json scripts or setup.py custom commands).
	- Logic: parse package.json `scripts[install|preinstall|postinstall|prepare]` for shell commands containing suspicious keywords (curl, wget, sh, npm, python -c) and compute AST for scripts when provided as inline JS.
	- Example: package.json `"install": "node -e \"require('child_process').exec('...')\""`

- `system_cmd_patterns` (int): number of occurrences of shell invocation tokens in string literals (e.g., `sh -c`, `bash -c`, `cmd.exe /c`).

### C. Network behavior

- `network_import_count` (int): number of imports or requires of network libraries (JS: `http`, `https`, `net`, `dns`, `request`, `axios`; Py: `requests`, `urllib`, `socket`).
	- Logic: AST Import/Require analysis and package.json dependencies.

- `network_call_count` (int): number of call-sites that perform outgoing communication (e.g., `http.request`, `fetch`, `axios.get`, `requests.get`, `socket.connect`).
	- Logic: AST CallExpression detection of known sink functions. When sink uses literal URL, parse and extract domain.

- `unique_domains` (int): number of distinct domains found in string literals used in network calls.

- `suspicious_tlds_count` (int): number of literals with IP addresses, rare TLDs, or punycode domains.

- `high_entropy_url_in_network_count` (int): number of network calls where the URL literal has entropy >= 4.5 (possible encoded payload in path/query).

- `exfiltration_score` (float): derived score between 0-1 combining sensitive data access + network call count + unique_domains. (Defined below in Combined features.)

### D. Sensitive data access

- `os_user_info_access_count` (int): occurrences accessing user home/name (JS: `os.userInfo()`, `process.env.USER`, Py: `os.getlogin()`, `pwd.getpwuid`).

- `env_read_count` (int): count of occurrences reading environment variables (`process.env`, `os.environ.get`, `os.getenv`).

- `secrets_access_paths_count` (int): file access (read/open) to sensitive path patterns: `~/.ssh`, `/etc/passwd`, `/etc/shadow`, `C:\\Users\\.*\\AppData\\Roaming`, `/.npmrc`, `/pip.conf`.

- `high_entropy_env_value_count` (int): env var literal that is high entropy (suggests hard-coded secrets or keys).

### E. File system interaction

- `file_read_count` (int): number of file read operations detected (JS `fs.readFileSync`/`fs.readFile`, Py `open(..., 'r')`, `Path.read_text`).

- `file_write_count` (int): number of write operations (`fs.writeFileSync`, `open(...,'w')`, `os.remove` for delete detection as separate feature).

- `sensitive_path_access_count` (int): file operations touching paths matching sensitive patterns (see D).

- `hidden_file_ops_count` (int): operations that create or modify hidden files (filenames starting with `.` or Windows hidden attributes — best-effort via names).

### F. Obfuscation & encoding

- `base64_literal_count` (int): number of literals that appear to be base64 (regex: ^[A-Za-z0-9+/=]{32,}$) and are used in code contexts.

- `base64_in_code_count` (int): number of base64 literals assigned to variables or passed to decoders (base64.b64decode, Buffer.from(...,'base64')).

- `hex_literal_count` (int): occurrences of long hex strings (length >= 32) used in code.

- `string_literal_entropy_mean` (float): mean entropy of all string literals encountered in code files.

- `identifier_entropy_mean` (float): mean entropy of identifiers (function/variable names) length>=4.

- `high_entropy_identifiers_count` (int): identifiers with entropy >= 4.5 (possible generated variable names used for obfuscation).

- `encoded_payload_chain_count` (int): number of observed chains where encoded literal (base64/hex) → decode function → eval/exec/Function/new Function is present in same scope or via dataflow (simple def/use tracking).
	- Logic: within the same function or top-level script, detect a literal that matches encoding pattern, a call to a decode function that uses that literal, and a subsequent call to eval/exec with decoder output.
	- Example JS: `const p='...'; const d=Buffer.from(p,'base64').toString(); eval(d);`

### G. Code structure anomalies

- `max_ast_depth` (int): maximum nesting depth of AST nodes in a file (measure recursion depth during traversal).

- `avg_function_length` (float): average number of AST nodes/statements per function.

- `dead_code_indicators` (int): heuristic count for unreachable constructs, e.g., immediately-returned function wrappers, repeated conditionals with constant false, or exceptionally large functions that are unused (static use-frequency analysis: function defined but never referenced in AST of package files).

- `weird_naming_ratio` (float): ratio of identifiers with non-alphanumeric characters or suspicious patterns (long random-looking names) to total identifiers.

- `lines_of_code` (int): conservative total source lines across code files.

### H. Dependency & package metadata

- `declared_dependencies_count` (int): number of dependencies declared in package.json or pyproject/requirements.

- `has_preinstall_script` (int): package.json scripts include `preinstall`.

- `has_install_script` (int): package.json scripts include `install`.

- `has_postinstall_script` (int): package.json scripts include `postinstall`.

- `install_scripts_exec_cmd_count` (int): number of shell commands within install scripts that appear to execute other programs (grep for `curl|wget|npm|python|node|sh|bash|powershell`).

- `bin_entries_count` (int): number of `bin` entries in package.json (may indicate CLI which can be abused).

- `setup_py_exec_count` (int): number of exec/spawn calls in `setup.py` / `pyproject` build hooks or PEP517 backend.

- `typosquatting_score` (float): fuzzy similarity score of package name vs top-100k npm/PyPI names (implementation: edit distance normalized by length, require external list).

## Derived / Combined Behavioral Features

These are critical. Compute them as boolean/int/float combinations during AST traversal and by joining context records.

- `exfiltration_score` (float): normalized 0-1 score computed as logistic combination of:
	- normalized sensitive data access count (env_read_count + secrets_access_paths_count)
	- normalized network_call_count
	- normalized unique_domains
	- presence multiplier if high_entropy literals are used as request arguments

	**Implementation**: compute sub-scores s1..s3 in [0,1] by capping counts, then exfiltration_score=Clamp( (0.45*s1 + 0.45*s2 + 0.1*s3) * (1 + 0.5*has_high_entropy_url_flag), 0, 1 )

- `obfuscated_execution_flag` (int): 1 if encoded_payload_chain_count >=1 OR (base64_in_code_count>0 AND eval_count>0 AND high_entropy_eval_count>0).

- `install_time_attack_flag` (int): 1 if install script exists AND (install_scripts_exec_cmd_count>0 OR install_time_exec_count>0).

- `high_entropy_execution_sinks` (int): count of occurrences where high entropy literal or decoded value reaches an execution sink (eval/exec/new Function/child_process.exec).

- `suspicious_package_entry` (int): 1 if package exposes a `bin` entry that maps to a script which performs elevated operations (child process/system access/network), determined by analyzing the target script.

## Ecosystem-specific sections

### npm (JavaScript)

- Parse `package.json` and extract: `name`, `version`, `scripts`, `bin`, `dependencies`, `optionalDependencies`, `peerDependencies`.
- Script features (each boolean/int): `has_preinstall_script`, `has_install_script`, `has_postinstall_script`, `install_scripts_exec_cmd_count`.
- Dynamic require patterns:
	- `dynamic_require_count` (int): occurrences of `require(variable)` where argument is not a Literal.
	- `eval_require_count` (int): occurrences where `require` is called with a concatenated string or computed expression.
- Node-specific APIs:
	- `child_process_*` counts as above.
	- `fs_*` read/write counts.
	- `process_env_usage_count` (int): occurrences accessing `process.env`.
- Browser vs Node detection:
	- `is_node_package` (int): presence of `main`, `bin`, or `dependencies` that require Node APIs.
	- `is_browser_package` (int): presence of `browser` field or usage of DOM APIs.

### PyPI (Python)

- Parse `pyproject.toml`, `setup.py`, `setup.cfg`, `requirements.txt`.
- Install hooks and entry points:
	- `entry_points_count` (int): number of console scripts/entry points declared.
	- `setup_py_exec_count` as above.
- Dynamic imports:
	- `dynamic_import_count` (int): occurrences of `__import__`, `importlib.import_module`, or `exec` used to import modules.

## Feature extraction algorithm (implementation-ready)

1. **Package-level preprocessing**
	 - Use `SafeExtractor` to extract archives to a temp dir.
	 - Enumerate files (limit scanning to reasonable max files/per package to avoid blow-up; maintain counters when truncated).
	 - Read metadata files first: package.json, pyproject.toml, setup.py. Parse them for declared dependencies and script hooks.

2. **File-level processing**
	 - For each file, read bytes once. Compute file entropy (fast vectorized method over bytes). Store per-file entropy if useful for summary metrics.
	 - If file suffix is code (.js/.mjs/.cjs/.ts? optional), parse with esprima (or a TS parser for .ts) into AST. For Python, use built-in `ast`.
	 - If file is large (configurable, default 1_000_000 bytes), fallback to fast regex/text scans and limited AST parsing where possible.

3. **AST traversal and context tracking**
	 - Maintain a traversal stack of context frames: module, function, class, statement. Each frame collects local records: defined identifiers, literals encountered, calls, assignments.
	 - When visiting Literal nodes (JS) or Constant/Str nodes (Python): compute entropy of value bytes if value is string and length >= 4; attach record: `{node_type, entropy, length, parent_frame_id, parent_construct}`.
	 - When visiting Identifier/Name nodes: compute identifier entropy if length>=4 and attach record.
	 - When visiting CallExpression/Call nodes: identify the sink (eval, exec, spawn, child_process, http.request, fetch, axios.* , requests.*, socket.connect, urllib.request) using a canonical sink registry and record a call event with references to argument nodes (by node id). If argument is a literal, attach entropy linkage.
	 - For assignments: if RHS is a call to a decoder (base64 decode / Buffer.from(...,'base64') / codecs.decode), record link between literal and variable name. When later that variable is used as argument to an execution sink, mark an encoded-payload chain.

4. **Correlation & derived features**
	 - After finishing AST for a file (or package-scoped analysis), join records by frame and variable names to detect chains: literal -> decode -> exec. Conservative alias resolution: track simple assignments and one-level flows (var a = '...'; var b = decode(a); eval(b)).
	 - For network exfiltration: join sensitive-data-access events (reading env, reading ~/.ssh, reading files matching patterns) to network_call events where arguments contain high-entropy strings or variable references resolved to previously-read sensitive data (best-effort static name matching: same variable name, same scope, or simple return/assign propagation).

5. **Efficiency & large file handling**
	 - Quick regex/text scans for large files: count occurrences of suspicious tokens (eval, exec, require('child_process'), base64-like literals) to avoid parsing expensive large ASTs.
	 - Cap per-package processed file count and per-file AST node count; if exceeded, set `truncated_scan_flag` and still report conservative counts from text scan.
	 - Use vectorized numpy entropy for raw byte arrays; cache entropy for repeated identical literals using an LRU memoization keyed by literal string.

6. **Output schema and example**
	 - All features listed in this doc MUST be present in the output row for every package. Use 0/False defaults for counts/bools, 0.0 for floats.

Example flat schema (subset for brevity):
```
{
	"package_name": str,
	"ecosystem": "NPM"|"PyPI",
	"label": 0|1,
	"max_entropy": float,
	"avg_entropy": float,
	"eval_count": int,
	"high_entropy_eval_count": int,
	"exec_count": int,
	"new_function_count": int,
	"child_process_spawn_count": int,
	"install_time_exec_count": int,
	"network_import_count": int,
	"network_call_count": int,
	"unique_domains": int,
	"exfiltration_score": float,
	"os_user_info_access_count": int,
	"env_read_count": int,
	"secrets_access_paths_count": int,
	"file_read_count": int,
	"file_write_count": int,
	"base64_literal_count": int,
	"encoded_payload_chain_count": int,
	"max_ast_depth": int,
	"avg_function_length": float,
	"declared_dependencies_count": int,
	"has_install_script": int,
	"typosquatting_score": float,
	"obfuscated_execution_flag": int,
	"install_time_attack_flag": int,
	"truncated_scan_flag": int,
	... (all others)
}
```

## Implementation tips and heuristics
- Maintain canonical lists of sink symbols and decoder functions for both ecosystems. Keep them in a config file so you can update heuristics without code changes.
- Use a node-id for AST nodes and lightweight records to enable cross-referencing without heavy symbolic analysis.
- For identifier resolution across files, support only intra-file resolution and top-level exports/imports by literal names; full inter-file dataflow is expensive and optional.
- Entropy memoization: maintain an LRU cache of computed entropies for string values to avoid repeated costs.

## Edge cases and mitigations
- Minified/one-line JS: treat many short identifiers but very long string literals carefully — rely on entropy and encoded-chain detection.
- Generated native modules, binary blobs: file-level entropy high but code-level features absent — still include file_entropy measures and `truncated_scan_flag`.
- False positives for legitimate tooling: many packages use `child_process` or base64 legitimately. Use combined features (e.g., base64 + eval + install script) to reduce false positives.

## Roadmap for integrating into current codebase
- The current repository already has `SafeExtractor`, `entropy.calculate_shannon_entropy`, and `ast_parser` with basic counts. Extend `ast_parser` to:
	- Compute and attach literal/identifier entropy during AST visits.
	- Emit context records for call-sites including literal node references.
	- Implement simple one-level dataflow tracking to detect encoded_payload_chain_count.
	- Expand known sink lists and add package metadata parsers for package.json and pyproject.toml.
- Update `build_dataset.py` to include all features in `row` and ensure output filename uses timestamp `dataset-DD-MM-YYYY-HHMMSS.csv` (already applied).

## Appendix: canonical lists (starter)
- **JS sinks**: eval, Function, setTimeout(string), setInterval(string), child_process.exec, child_process.execSync, child_process.spawn, vm.runInThisContext, vm.runInNewContext, http.request, https.request, net.connect, dns.resolve, fetch, XMLHttpRequest
- **Py sinks**: eval, exec, compile(..., 'exec'), subprocess.Popen/call/run, os.system, socket.socket.connect, requests.request, urllib.request.urlopen
- **Decoders**: base64.b64decode, Buffer.from(...,'base64'), codecs.decode(...,'base64'), decodeHex helpers

For questions about thresholds, performance tuning, or adding new heuristics, open an issue in the repository referencing this document.

