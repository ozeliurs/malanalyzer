# Malanalyzer Helm chart

Deploys the website/API and a dedicated analysis worker, with native Kubernetes Jobs for individual investigations. Images are published by `.github/workflows/images.yml`:

- `ghcr.io/ozeliurs/malanalyzer` — FastAPI, worker, OpenCode, kubectl and Docker CLI.
- `ghcr.io/ozeliurs/malanalyzer-tools` — offline analysis tools, Python libraries and the bounded command runner.

Both images are built for `linux/amd64` and `linux/arm64`. A push to `main` publishes `latest` and `sha-<full-commit-SHA>` tags. A `vX.Y.Z` Git tag also publishes `X.Y.Z` and `X.Y`. Pull requests validate/build without publishing. No Mistral credential is needed in GitHub Actions; registry publishing uses `GITHUB_TOKEN` with `packages: write`.

## Architecture

```text
Ingress / Service
       │
StatefulSet (one pod)
  ├── API
  ├── worker + OpenCode / Mistral
  └── shared ReadWriteOnce PVC: SQLite, samples, transcripts
          │
          └── per-analysis Kubernetes Job, scheduled on the same node
                ├── read-only subPath mount of this sample only
                ├── memory-backed /workspace and /tmp
                ├── non-root, read-only root filesystem, no service account token
                └── default-deny ingress and egress NetworkPolicy
```

The worker creates and executes commands in analysis Jobs using its projected Kubernetes service-account token. Only the worker container mounts that token. Analysis containers receive neither the Mistral key nor Kubernetes credentials. There is no privileged container, Docker socket or Docker-in-Docker daemon in this deployment. The Docker backend remains available for local development.

**Storage:** use an ext4/XFS, block-backed **ReadWriteOnce** PVC and a CSI driver that supports `fsGroup`/subPath file mounts. SQLite/WAL requires local filesystem locking; NFS is unsupported. `ReadWriteOncePod` cannot be used because the server pod and analysis pod mount the same claim concurrently. The Job's node affinity keeps its mount on the server's node. The server has exactly one replica; tune `worker.concurrency` for concurrent analyses on that node. Multi-node API/worker scaling requires moving SQLite and sample storage to shared services.

The chart creates a default-deny policy for analysis pods. The cluster CNI must enforce Kubernetes NetworkPolicy (for example Cilium or Calico). If the namespace has additional default-deny policies, allow the server pod to reach DNS, the Kubernetes API and Mistral's API; analysis pods need no network access. The bundled kubectl is v1.34.1; use the Docker build argument `KUBECTL_VERSION` for a client matching your cluster's supported version skew.

## Install

After the image workflow has succeeded, create a namespace and credential Secret. Set `MISTRAL_API_KEY` in your shell or supply this Secret through your existing secret manager:

```bash
kubectl create namespace malanalyzer
kubectl -n malanalyzer create secret generic malanalyzer-secrets \
  --from-literal=MISTRAL_API_KEY="$MISTRAL_API_KEY"
```

To restrict uploads, also include `--from-literal=UPLOAD_API_KEY="$UPLOAD_API_KEY"` when creating the Secret. Reports remain public.

If the GHCR packages are private, create a registry Secret with a token that can read both packages:

```bash
kubectl -n malanalyzer create secret docker-registry ghcr-credentials \
  --docker-server=ghcr.io \
  --docker-username="$GHCR_USERNAME" \
  --docker-password="$GHCR_TOKEN"
```

Install from the repository checkout, using an immutable image tag from the successful build:

```bash
helm upgrade --install malanalyzer ./charts/malanalyzer \
  --namespace malanalyzer \
  --set-string image.tag="sha-$(git rev-parse HEAD)" \
  --set 'imagePullSecrets[0].name=ghcr-credentials' \
  --wait --timeout 5m
```

Omit the `imagePullSecrets` override for public images. The analysis image automatically uses the same tag and inherits the registry credentials. Override `persistence.storageClass` if your cluster has no suitable default StorageClass. Initial image pulls can take longer than a cached start; adjust `analysis.startupTimeoutSeconds` if needed.

Access the website:

```bash
kubectl -n malanalyzer port-forward service/malanalyzer 8001:80
```

Then open <http://127.0.0.1:8001>. To expose it through ingress/TLS, put your overrides in a values file:

```yaml
image:
  tag: sha-REPLACE_WITH_THE_BUILT_COMMIT_SHA
imagePullSecrets:
  - name: ghcr-credentials
persistence:
  storageClass: your-block-storage-class
  size: 20Gi
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "26m"
  hosts:
    - host: malware.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: malanalyzer-tls
      hosts:
        - malware.example.com
```

Apply with `helm upgrade --install malanalyzer ./charts/malanalyzer -n malanalyzer -f your-values.yaml --wait`. The ingress upload limit must allow multipart overhead above `config.maxUploadMb` (25 MiB by default).

## Important values

See `values.yaml` for the complete configuration.

| Value | Default | Purpose |
| --- | --- | --- |
| `image.repository`, `image.tag` | `ghcr.io/ozeliurs/malanalyzer`, `latest` | API/worker image; use a SHA or release tag in production |
| `analysis.image.repository`, `.tag` | inherited | Defaults to `<image.repository>-tools` with the API tag |
| `imagePullSecrets` | `[]` | Kubernetes registry Secrets for server and analysis images |
| `analysis.imagePullSecrets` | `[]` | Optional override, a list of Secret names |
| `secrets.existingSecret` | `malanalyzer-secrets` | Existing Secret containing Mistral and optional upload credentials |
| `persistence.existingClaim` | empty | Use an existing claim instead of creating one |
| `persistence.size`, `.storageClass` | `20Gi`, cluster default | Storage allocation; `storageClass: "-"` disables dynamic/default class selection |
| `persistence.retain` | `true` | Keep the chart-created PVC on uninstall |
| `worker.concurrency` | `1` | Concurrent analysis consumers in the server pod |
| `config.model` | `mistral/mistral-large-4` | Analysis model |
| `config.analysisTimeoutSeconds` | `1800` | Investigation deadline |
| `config.analysisMaxToolCalls` | `100` | Tool-call budget |
| `analysis.memoryMb`, `.cpuLimit` | `2048`, `2` | Per-analysis resource limits |
| `analysis.memoryRequest`, `.cpuRequest` | `256Mi`, `250m` | Per-analysis scheduler requests |
| `analysis.startupTimeoutSeconds` | `180` | Image-pull/scheduling wait |
| `analysis.jobTtlSeconds` | `120` | Job cleanup TTL after completion/failure |
| `analysis.runtimeClassName` | empty | Optional sandboxed container runtime supported by your nodes |
| `nodeSelector`, `tolerations`, `affinity` | empty | Placement of the server; analysis Jobs follow its node and inherit tolerations |
| `api.resources`, `worker.resources` | see values | Server container resource requests/limits |
| `api.extraEnv`, `worker.extraEnv` | `[]` | Additional Kubernetes EnvVar entries |
| `ingress.*` | disabled | Ingress class, hosts, annotations and TLS |

If you supply `serviceAccount.name` or `analysisServiceAccount.name`, create that account beforehand. The chart's RoleBinding grants the worker account namespace-scoped Job and pod-exec access; the analysis account has no chart-created RoleBinding.

## Operations

```bash
kubectl -n malanalyzer rollout status statefulset/malanalyzer
kubectl -n malanalyzer logs malanalyzer-0 -c api
kubectl -n malanalyzer logs malanalyzer-0 -c worker -f
kubectl -n malanalyzer get jobs,pods -l app.kubernetes.io/component=analysis
kubectl -n malanalyzer describe job JOB_NAME
```

Investigation logs and reports survive container restarts on `/data`. On normal completion, analysis Jobs are deleted; active deadlines, TTL cleanup and owner references cover abandoned Jobs. Worker interruptions are retried using the existing queue leases and attempt limit. To load changed Secret values, restart the StatefulSet (`kubectl -n malanalyzer rollout restart statefulset/malanalyzer`).

Back up the PVC with a CSI snapshot or a coordinated SQLite backup. With the default retention setting, `helm uninstall` keeps the PVC. Reuse it through `persistence.existingClaim` when reinstalling if Helm reports that the retained claim already exists.

## Validate locally

```bash
helm lint charts/malanalyzer --strict
helm template malanalyzer charts/malanalyzer -n malanalyzer
pytest -q tests/test_kubernetes.py
docker build -t malanalyzer-app:local .
docker build -f sandbox/Dockerfile -t malanalyzer-tools:local .
```
