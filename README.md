# Malanalyzer

A FastAPI website and **tool-driven malware reverse-engineering pipeline**. Upload a binary or script; OpenCode investigates its actual bytes with Mistral Large 4, follows disassembly and decoding leads, and writes a freeform Markdown report. Completed reports are automatically published at **`/reports`**.

The workflow follows an iterative reverse-engineering session: inspection, targeted disassembly, cross-reference searches, analyst-authored Python decoders, and bounded Unicorn emulation. The initial evidence preview is a starting point; the agent can inspect the full sample throughout the investigation.

**The current deliverable is a Markdown report.** Recovered configuration, indicators, behavior, attribution and uncertainty belong in that report. New analyses do not generate structured IOC JSON or require a JSON response envelope.

## Kubernetes deployment and container images

The production `Dockerfile` packages the API/worker with OpenCode and kubectl. GitHub Actions builds both application and analysis-tool images for AMD64/ARM64 and pushes them to **`ghcr.io/ozeliurs/malanalyzer`** and **`ghcr.io/ozeliurs/malanalyzer-tools`** on pushes to `main` and version tags.

The Helm chart at [`charts/malanalyzer`](charts/malanalyzer/README.md) deploys the API and worker together on a persistent volume, plus namespace-scoped RBAC, Service, optional ingress/TLS, and an offline-analysis NetworkPolicy. In Kubernetes mode, each investigation runs in a native **Kubernetes Job** with only its sample mounted read-only. The chart uses existing Kubernetes Secrets for credentials and registry authentication. See the chart README for installation commands, storage requirements, values and operations.

```bash
docker build -t malanalyzer-app:local .
docker build -f sandbox/Dockerfile -t malanalyzer-tools:local .
helm lint charts/malanalyzer --strict
```

## Run locally

Requires **Python 3.12+**, **Docker with a running local daemon**, and **OpenCode V1** on your `PATH`. The live workflow was verified with **OpenCode 1.19.5** and **`mistral/mistral-large-4`**.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
docker build -f sandbox/Dockerfile -t malanalyzer-tools:local .
uvicorn malanalyzer.app:app --reload --host 127.0.0.1 --port 8001
```

- Website: <http://127.0.0.1:8001/>
- Reports: <http://127.0.0.1:8001/reports>
- Interactive API: <http://127.0.0.1:8001/docs>

Copy `.env.example` to the git-ignored `.env` on a fresh checkout and set `MISTRAL_API_KEY`. The key is used by OpenCode to contact Mistral; it is not sent to the browser or the analysis container.

Restart API/worker processes after changing environment settings. Each investigation starts a fresh OpenCode process with its own runtime config, HOME and XDG directories. Your personal OpenCode configuration is not modified. If editing your own OpenCode configuration separately, quit and restart that session to load its changes.

## Investigation flow

```text
Upload → SHA-256 sample storage → durable SQLite job
       → offline Docker workspace + initial evidence
       → OpenCode / Mistral Large 4 ↔ analysis tools (MCP)
       → final Markdown report → atomic publication → /reports
```

1. **Upload:** enforce sample/request-size limits, hash and store the file, then return a job ID immediately. Identical uploads share a blob; each submission has its own analysis job.
2. **Prepare:** start a disposable container, mount a read-only snapshot at `/input/sample.bin`, and collect an initial preview of hashes, sections, imports, strings, entropy and entry-point disassembly. The preview is bounded to keep the initial context useful.
3. **Investigate:** the agent uses the tools below to inspect the entire file, follow functions/references, write analysis scripts, recover encoded strings/configuration, and verify hypotheses. Files under `/workspace` persist across tool calls in that job. Python variables do not persist between calls; scripts can be saved and rerun.
4. **Write:** the agent calls `analysis_write_report` with the complete Markdown report. Intermediate chat is not treated as the report. The agent must perform a successful investigation call before finalizing.
5. **Publish:** read the finalized report from inside the container, validate its size/content, derive a title and summary from its Markdown, and publish it in one database transaction. Family attribution, configuration and indicators stay in the narrative. A session that ends without finalizing a report fails rather than publishing intermediate commentary.
6. **Clean up:** remove the container and temporary analysis files, retaining private tool/session transcripts for reproducibility. Failed jobs retry according to `MAX_ATTEMPTS`.

Every new report ends with a backend-generated **Analysis cost** section: the estimated model API cost in **USD**, model, completed model turns, and reported token usage. It sums OpenCode's per-turn cost estimates, including the final model response after report delivery. The footer appears on the website and in Markdown downloads. Estimates cover the successful analysis session, excluding infrastructure and previous failed attempts; the provider's invoice may differ. Missing pricing is labeled unavailable or partial rather than displayed as free.

The upload page shows the current tool activity and invocation count during the investigation. Complex samples can take several minutes; the default investigation budget is 30 minutes.

## Tools available to the AI

OpenCode's host shell/filesystem tools are denied. The agent has these MCP tools instead:

| Tool | Purpose |
| --- | --- |
| `analysis_run_command` | Run static-analysis commands and analyst-authored scripts in the offline container |
| `analysis_run_python` | Write/run Python for parsing, xrefs, decoding, cryptography, and targeted Unicorn emulation |
| `analysis_disassemble` | Capstone disassembly at a PE/ELF virtual address or entry point, with resolved x86/x64 RIP-relative targets |
| `analysis_find_xrefs` | Scan x86/x64 executable sections for references to an address or address range |
| `analysis_write_report` | Save the complete final Markdown report; remains available after the investigative-call budget is exhausted |

Preinstalled command-line tools: **`file`, `strings`, `objdump` (multiarch), `readelf`, `nm`, `xxd`, `grep`, Bash, Python 3**.

Preinstalled Python libraries: **pefile, pyelftools, Capstone, Unicorn, cryptography, PyCryptodome**. Tools are built into the image; there is no package installation during investigation.

### Address-aware Python helper

`malanalyzer.binary_tools.BinaryImage` is available inside the container:

```python
from malanalyzer.binary_tools import BinaryImage

image = BinaryImage('/input/sample.bin')
print(hex(image.image_base), hex(image.entry))
print(image.sections)
print(list(image.disassemble(image.entry, size=1024, count=200)))
print(list(image.xrefs(0x140099000, 0x140099400)))
blob = image.read(0x140099064, 128)
```

Its public addresses are **VAs**. For PE, an RVA is `VA - ImageBase`, not `VA - section base`. The helper covers PE/ELF x86/x64/ARM64 disassembly; its xref scanner supports x86/x64 and skips embedded invalid bytes rather than terminating the entire scan. Computed/indirect references may still require custom scripts. For other formats/architectures the agent can use the installed tools directly.

### Report expectations

The prompt asks the agent to:

- Inspect entry points and relevant callees/call sites, rather than infer behavior from imports alone.
- Investigate encrypted strings and configuration by deriving decoders from instructions and actually running those decoders.
- Verify address mapping, byte/word widths, loop bounds, indices and null termination.
- Use bounded Unicorn emulation with stubbed APIs when useful, documenting initialization assumptions and failures.
- Cite evidence addresses, explain recovery methods, distinguish proven behavior from probable capability, and describe unresolved gaps.
- Use its own Markdown organization and include indicators/configuration naturally in prose or tables.
- Avoid unsupported family claims and invented runtime observations.

This is a static-analysis workflow with optional focused emulation, not native detonation. The agent is instructed not to launch/import the sample or extracted payloads. Full decompilation is not provided by a preconfigured Ghidra/IDA service; the available workflow uses disassembly, parser libraries, custom scripts and emulation, as in the reference session. Analysis depth still depends on the sample, model and budget.

## Workspace isolation and transcripts

For local development (`SANDBOX_BACKEND=docker`), each job gets a Docker container with:

- **No network**, no API credentials, no Docker socket, and no project/host filesystem mounts beyond the submitted snapshot.
- Non-root UID/GID, read-only root filesystem, dropped capabilities, and no-new-privileges.
- Read-only input; writable, size-bounded `/workspace` and `/tmp` tmpfs mounts with `noexec`.
- Memory, CPU and process limits; per-command time/output bounds; an overall investigation deadline.
- Automatic removal and a finite container lifetime, including if the worker crashes.

OpenCode stays outside this offline container so it can call Mistral. Its analysis tools communicate through the trusted local MCP bridge, which sends commands into the container. Source/string previews and tool results are sent to Mistral as part of the model context.

The Helm deployment sets `SANDBOX_BACKEND=kubernetes`: the same bridge uses `kubectl exec` in a bounded Kubernetes Job, a read-only single-file PVC mount, memory-backed scratch volumes, and a NetworkPolicy instead of Docker networking. API/worker and analysis pods need no privileged mode or Docker daemon. See the [chart architecture](charts/malanalyzer/README.md#architecture) for storage and CNI requirements.

Transcripts are retained under:

```text
data/sessions/<job-id>-<attempt-id>/
  tools.jsonl             tool inputs, bounded outputs, timestamps and status
  opencode-events.jsonl   machine-readable OpenCode session events, when the CLI finishes
```

These files are private local artifacts, not public download routes. They capture investigation steps and scripts; they are not copied from the reference session. Container files and emulated payloads are discarded at cleanup. On timeout, the incremental tool audit is retained even if the OpenCode event stream could not be saved.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/samples` | Upload multipart `file`; receive a job (`202`) |
| `GET` | `/api/analyses/{id}` | Status, stage, attempt count, tool count, activity and report URL |
| `GET` | `/api/reports?limit=20&offset=0&q=` | Paginated public report summaries; title/SHA-256 search |
| `GET` | `/api/reports/{id}` | Report metadata and Markdown |
| `GET` | `/api/reports/{id}/markdown` | Download the final Markdown report |
| `GET` | `/health` | Process health and credential-presence indicator |

```bash
curl -F 'file=@/path/to/sample.exe' http://127.0.0.1:8001/api/samples
curl http://127.0.0.1:8001/api/analyses/JOB_ID
curl -o report.md http://127.0.0.1:8001/api/reports/JOB_ID/markdown
```

If `UPLOAD_API_KEY` is configured, include `-H 'X-API-Key: YOUR_UPLOAD_KEY'` in the upload request. Reports remain public.

For compatibility, the existing IOC schemas/database column and `/api/reports/{id}/iocs` endpoint remain available for older reports. New reports leave the IOC array empty and hide the IOC JSON download/table. No new structured-IOC output is generated.

## Configuration

Environment variables override `.env`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `MISTRAL_API_KEY` | empty | Mistral credential |
| `OPENCODE_MODEL` | `mistral/mistral-large-4` | Model for tool-driven investigation |
| `OPENCODE_BINARY` | `opencode` | OpenCode V1 executable or absolute path |
| `DOCKER_BINARY` | `docker` | Docker executable or absolute path |
| `SANDBOX_BACKEND` | `docker` | `docker` locally; `kubernetes` in the Helm deployment |
| `SANDBOX_IMAGE` | `malanalyzer-tools:local` | Prebuilt local tools image; no runtime pulling |
| `SANDBOX_MEMORY_MB` | `2048` | Container memory bound |
| `DATA_DIR` | `./data` | Sample storage, SQLite queue/reports and private transcripts |
| `MAX_UPLOAD_MB` | `25` | Maximum sample size in MiB |
| `ANALYSIS_TIMEOUT_SECONDS` | `1800` | Overall OpenCode investigation deadline |
| `ANALYSIS_MAX_STEPS` | `120` | Maximum OpenCode agent turns |
| `ANALYSIS_MAX_TOOL_CALLS` | `100` | Investigative tool budget, separate from report delivery |
| `TOOL_TIMEOUT_SECONDS` | `120` | Maximum duration of a tool command |
| `STATIC_TIMEOUT_SECONDS` | `60` | Initial evidence collection timeout |
| `EMBEDDED_WORKER` | `true` | Run workers inside the API process |
| `WORKER_CONCURRENCY` | `1` | Consumer loops per process |
| `MAX_ATTEMPTS` | `2` | Automatic attempts before terminal failure |
| `LEASE_SECONDS` | `90` | Job lease duration, renewed while investigating |
| `POLL_SECONDS` | `1` | Queue polling interval |
| `UPLOAD_API_KEY` | empty | Optional upload key, separate from the Mistral credential |

Keep the turn budget higher than the investigative-call budget to leave room for report delivery. The call results include remaining call/time budgets. Long-running reasoning models may need a larger overall timeout than non-reasoning models.

### Separate API and worker

Use the same local `DATA_DIR`, Python environment and Docker context:

```bash
EMBEDDED_WORKER=false uvicorn malanalyzer.app:app --host 127.0.0.1 --port 8001
```

In another terminal:

```bash
malanalyzer-worker
```

Workers claim jobs atomically, renew leases, and recover crashed jobs after lease expiry. Stale owners cannot publish. SQLite and sample bind mounts target a single-host deployment; remote Docker daemons/multi-host workers require shared sample/queue infrastructure. Only `static/` assets and report pages are served publicly. Public hosting should use a reverse proxy with a request-body limit allowing multipart overhead above the sample limit. Define retention/backups for `data/`, including its private transcripts.

## Verification

```bash
pytest -q
RUN_SANDBOX_TESTS=1 pytest -q
ruff check .
```

The default suite tests the API/queue/report flow, old-DB-compatible schema initialization, retries and leases, address mapping, PE/ELF disassembly, xrefs through embedded data, Markdown rendering and report-only output. `RUN_SANDBOX_TESTS=1` additionally exercises the real Docker/MCP bridge, offline/credential-free tools, read-only input, tool time/output bounds, and final-report delivery.

For a live Mistral/OpenCode investigation of an inert ELF containing an XOR-obfuscated URL:

```bash
python scripts/smoke.py
# Optional: keep the generated report and transcripts for inspection.
python scripts/smoke.py --keep data/smoke-verification
```

This test requires actual disassembly and recovery of the hidden URL, not merely successful API calls or a plausible report. It uses temporary job storage, sends tool evidence to Mistral, and incurs normal API usage. The verified Large 4 run recovered the string with Python and confirmed it using Unicorn.

## Future family modules

`malanalyzer/modules.py` retains the future contracts for family matches and deterministic configuration extractors. YARA identification plus versioned Python extractors remains a suitable extension. Automatic module generation/loading and structured IOC extraction are deferred while the investigative Markdown-report workflow is developed.
