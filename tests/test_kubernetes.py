import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from malanalyzer.analyzer import opencode_config
from malanalyzer.config import Settings
from malanalyzer.kubernetes_sandbox import (
    KubernetesClient,
    KubernetesSandbox,
    kubernetes_environment,
)
from malanalyzer.process import ProcessError, failure_reason
from malanalyzer.sandbox import create_sandbox


def kube_settings(tmp_path, **overrides):
    return Settings(
        _env_file=None, data_dir=tmp_path, sandbox_backend="kubernetes",
        kubernetes_namespace="analysis-team", kubernetes_pvc_name="sample-data",
        kubernetes_node_name="worker-node", kubernetes_worker_pod_name="malanalyzer-0",
        kubernetes_worker_pod_uid="pod-uid", kubernetes_instance="test-release",
        sandbox_image="ghcr.io/example/malanalyzer-tools:sha-123",
        kubernetes_analysis_service_account="unprivileged-analysis", **overrides,
    )


def test_analysis_job_is_scoped_offline_ready_and_mounts_only_its_sample(tmp_path, monkeypatch):
    monkeypatch.setattr("malanalyzer.kubernetes_sandbox.shutil.which", lambda _: "/usr/bin/kubectl")
    config = kube_settings(tmp_path, kubernetes_image_pull_secrets=["ghcr-pull"])
    sandbox = create_sandbox(config, tmp_path / "sample", tmp_path / "runs" / "attempt")
    assert isinstance(sandbox, KubernetesSandbox)
    manifest = sandbox.manifest()
    assert manifest["kind"] == "Job"
    assert manifest["metadata"]["namespace"] == "analysis-team"
    assert manifest["metadata"]["ownerReferences"][0]["uid"] == "pod-uid"
    assert manifest["spec"]["backoffLimit"] == 0
    assert manifest["spec"]["activeDeadlineSeconds"] > config.analysis_timeout_seconds
    assert manifest["spec"]["ttlSecondsAfterFinished"] == 120
    pod = manifest["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["serviceAccountName"] == "unprivileged-analysis"
    assert pod["imagePullSecrets"] == [{"name": "ghcr-pull"}]
    container = pod["containers"][0]
    assert container["image"] == config.sandbox_image
    assert container["securityContext"]["readOnlyRootFilesystem"]
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert container["volumeMounts"][0] == {
        "name": "input", "mountPath": "/input/sample.bin", "subPath": "runs/attempt/input/sample.bin", "readOnly": True,
    }
    assert "env" not in container
    assert pod["volumes"][0]["persistentVolumeClaim"] == {"claimName": "sample-data", "readOnly": True}
    affinity = pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
    assert affinity["nodeSelectorTerms"][0]["matchFields"][0]["values"] == ["worker-node"]
    assert manifest["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/component"] == "analysis"


def test_kubernetes_tool_bridge_reuses_protocol_without_docker_or_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr("malanalyzer.kubernetes_sandbox.shutil.which", lambda _: "/usr/bin/kubectl")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("MISTRAL_API_KEY", "not-for-the-sandbox")
    config = kube_settings(tmp_path)
    sandbox = create_sandbox(config, tmp_path / "sample", tmp_path)
    encoded = opencode_config(config.opencode_model, sandbox, config, tmp_path / "tools.jsonl")
    command = encoded["mcp"]["analysis"]["command"]
    assert command[command.index("--backend") + 1] == "kubernetes"
    assert command[command.index("--namespace") + 1] == "analysis-team"
    assert encoded["mcp"]["analysis"]["environment"]["KUBERNETES_SERVICE_HOST"] == "10.0.0.1"
    assert "MISTRAL_API_KEY" not in kubernetes_environment()

    async def checks():
        client = KubernetesClient("kubectl", sandbox.name, tmp_path, "analysis-team")
        calls = []
        async def fake_kubectl(*args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == "get":
                return json.dumps({"items": [{"metadata": {"name": "analysis-pod"}, "status": {
                    "phase": "Running", "containerStatuses": [{"name": "analysis", "state": {"running": {"startedAt": "now"}}}],
                }}]}).encode(), b""
            return b'{"exit_code":0,"stdout":"decoded","stderr":"","timed_out":false,"truncated":false}', b""
        client.kubectl = fake_kubectl
        output = await client.execute("python", "print('decoded')", 120)
        assert output["stdout"] == "decoded"
        assert calls[-1][0][:5] == ("exec", "-i", "analysis-pod", "--container", "analysis")
        payload = json.loads(calls[-1][1]["input_data"])
        assert payload["code"] == "print('decoded')"
        assert calls[-1][1]["timeout"] == 135
    asyncio.run(checks())


def test_kubectl_preserves_in_cluster_fallback_and_bounds_timeout_externally(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.43.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    calls = []

    async def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return b"job created", b""

    monkeypatch.setattr("malanalyzer.kubernetes_sandbox.run_bounded", fake_run)
    client = KubernetesClient("kubectl", "malanalyzer-" + "a" * 32, tmp_path, "malanalyzer")
    asyncio.run(client.kubectl("create", "-f", "-", timeout=135, input_data=b"{}"))
    command, options = calls[0]
    assert command == ["kubectl", "--namespace", "malanalyzer", "create", "-f", "-"]
    assert not any(arg.startswith("--request-timeout") for arg in command)
    assert options["timeout"] == 135
    assert options["input_data"] == b"{}"
    assert options["env"]["KUBERNETES_SERVICE_HOST"] == "10.43.0.1"
    assert options["env"]["KUBERNETES_SERVICE_PORT"] == "443"


@pytest.mark.parametrize(("stderr", "expected"), [
    (b'Get "http://localhost:8080/openapi/v2": connection refused', "in-cluster credentials"),
    (b'jobs.batch is forbidden: User cannot create resource jobs', "namespace-scoped RBAC"),
    (b'error: You must be logged in to the server (Unauthorized)', "service-account token"),
])
def test_kubernetes_errors_have_actionable_safe_messages(stderr, expected):
    assert expected in failure_reason(b"", stderr, 1)


def test_kubernetes_job_stages_sample_and_cleans_up_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("malanalyzer.kubernetes_sandbox.shutil.which", lambda _: "/usr/bin/kubectl")
    config = kube_settings(tmp_path)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    sample = tmp_path / "sample"
    sample.write_bytes(b"inert fixture")
    sandbox = create_sandbox(config, sample, run_dir)
    calls = []
    async def fake_kubectl(*args, **kwargs):
        calls.append(args)
        if args[0] == "get":
            return b'{"items":[{"status":{"phase":"Failed"}}]}', b""
        return b"", b""
    sandbox.kubectl = fake_kubectl
    async def checks():
        with pytest.raises(ProcessError, match="stopped"):
            async with sandbox:
                pytest.fail("A failed pod must not start analysis")
    asyncio.run(checks())
    assert (run_dir / "input" / "sample.bin").read_bytes() == b"inert fixture"
    assert calls[0] == ("create", "-f", "-")
    assert calls[-1][:3] == ("delete", "job", sandbox.name)


@pytest.mark.skipif(not shutil.which("helm"), reason="Helm is required for chart rendering tests")
def test_helm_defaults_and_private_registry_ingress_overrides(tmp_path):
    chart = Path(__file__).resolve().parents[1] / "charts" / "malanalyzer"
    def render(*extra):
        output = subprocess.run(
            ["helm", "template", "malanalyzer", str(chart), "--namespace", "analysis-team", *extra],
            check=True, capture_output=True, text=True,
        )
        return [item for item in yaml.safe_load_all(output.stdout) if item]
    documents = render()
    statefulset = next(item for item in documents if item["kind"] == "StatefulSet")
    assert statefulset["metadata"]["name"] == "malanalyzer"
    assert statefulset["spec"]["replicas"] == 1
    pod = statefulset["spec"]["template"]["spec"]
    assert not pod["automountServiceAccountToken"]
    api, worker = pod["containers"]
    assert not any(mount["name"] == "kubernetes-api" for mount in api["volumeMounts"])
    assert any(mount["name"] == "kubernetes-api" for mount in worker["volumeMounts"])
    assert pod["securityContext"]["fsGroup"] == 10001
    policy = next(item for item in documents if item["kind"] == "NetworkPolicy")
    assert policy["spec"]["egress"] == [] and policy["spec"]["ingress"] == []
    config = next(item for item in documents if item["kind"] == "ConfigMap")["data"]
    assert config["SANDBOX_BACKEND"] == "kubernetes"
    assert config["SANDBOX_IMAGE"] == "ghcr.io/ozeliurs/malanalyzer-tools:latest"
    pvc = next(item for item in documents if item["kind"] == "PersistentVolumeClaim")
    assert pvc["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]

    overrides = tmp_path / "values.yaml"
    overrides.write_text(yaml.safe_dump({
        "image": {"repository": "ghcr.io/example/private", "tag": "sha-123"},
        "imagePullSecrets": [{"name": "pull-secret"}],
        "persistence": {"existingClaim": "existing-data"},
        "ingress": {"enabled": True, "className": "nginx", "tls": [{"secretName": "site-tls", "hosts": ["malanalyzer.example.com"]}]},
        "tolerations": [{"key": "analysis", "operator": "Exists"}],
    }))
    documents = render("-f", str(overrides))
    assert not any(item["kind"] == "PersistentVolumeClaim" for item in documents)
    assert any(item["kind"] == "Ingress" for item in documents)
    config = next(item for item in documents if item["kind"] == "ConfigMap")["data"]
    assert config["SANDBOX_IMAGE"] == "ghcr.io/example/private-tools:sha-123"
    assert json.loads(config["KUBERNETES_IMAGE_PULL_SECRETS"]) == ["pull-secret"]
    assert json.loads(config["KUBERNETES_TOLERATIONS"]) == [{"key": "analysis", "operator": "Exists"}]
    assert config["KUBERNETES_PVC_NAME"] == "existing-data"
