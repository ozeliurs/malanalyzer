import asyncio
import contextlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from malanalyzer.config import Settings
from malanalyzer.process import ProcessError, base_environment, run_bounded
from malanalyzer.sandbox import SandboxClient


def kubernetes_environment() -> dict[str, str]:
    names = ("KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "KUBERNETES_SERVICE_PORT_HTTPS")
    # kubectl's discovery cache must be writable with a read-only worker root filesystem.
    return base_environment() | {"HOME": "/tmp"} | {name: os.environ[name] for name in names if name in os.environ}


class KubernetesClient(SandboxClient):
    """Reuse the tool protocol, executing inside one named analysis Job instead of Docker."""

    def __init__(self, binary: str, name: str, cwd: Path, namespace: str):
        super().__init__(binary, name, cwd)
        self.namespace = namespace
        self.pod_name = None

    async def kubectl(self, *arguments, timeout=30, **kwargs):
        return await run_bounded(
            [self.binary, "--namespace", self.namespace, f"--request-timeout={timeout}s", *arguments],
            cwd=self.cwd, env=kubernetes_environment(), timeout=timeout, **kwargs,
        )

    async def running_pod(self) -> str | None:
        output, _ = await self.kubectl(
            "get", "pods", "--selector", f"malanalyzer.analysis={self.name}", "-o", "json",
        )
        for pod in json.loads(output).get("items", []):
            status = pod.get("status", {})
            if status.get("phase") == "Running" and any(
                item.get("name") == "analysis" and item.get("state", {}).get("running")
                for item in status.get("containerStatuses", [])
            ):
                return pod["metadata"]["name"]
            if status.get("phase") in ("Failed", "Succeeded"):
                raise ProcessError("The Kubernetes analysis container stopped before investigation completed.")
        return None

    async def exec(self, *command, timeout=30, input_data=None, **kwargs):
        if self.pod_name is None:
            self.pod_name = await self.running_pod()
        if not self.pod_name:
            raise ProcessError("The Kubernetes analysis container is not running.")
        flags = ["-i"] if input_data is not None else []
        return await self.kubectl(
            "exec", *flags, self.pod_name, "--container", "analysis", "--", *command,
            timeout=timeout, input_data=input_data, **kwargs,
        )


class KubernetesSandbox(KubernetesClient):
    def __init__(self, settings: Settings, sample: Path, run_dir: Path):
        binary = shutil.which(settings.kubectl_binary)
        if not binary:
            raise ProcessError("kubectl executable not found in the worker image.")
        if not settings.kubernetes_pvc_name or not settings.kubernetes_node_name:
            raise ProcessError("Kubernetes analysis requires KUBERNETES_PVC_NAME and KUBERNETES_NODE_NAME.")
        super().__init__(binary, f"malanalyzer-{uuid.uuid4().hex}", run_dir, settings.kubernetes_namespace)
        self.settings, self.sample = settings, sample

    def manifest(self) -> dict:
        settings = self.settings
        relative = (self.cwd / "input" / "sample.bin").relative_to(settings.root)
        labels = {
            "app.kubernetes.io/instance": settings.kubernetes_instance,
            "app.kubernetes.io/component": "analysis", "malanalyzer.analysis": self.name,
        }
        lifetime = settings.analysis_timeout_seconds + settings.static_timeout_seconds + 120
        pod_spec = {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "serviceAccountName": settings.kubernetes_analysis_service_account,
            "enableServiceLinks": False, "terminationGracePeriodSeconds": 5,
            # Match the data PVC's group to avoid ownership churn while mounting its one input file.
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                "fsGroup": 10001, "fsGroupChangePolicy": "OnRootMismatch",
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": [settings.kubernetes_node_name]}]},
            ]}}},
            "imagePullSecrets": [{"name": name} for name in settings.kubernetes_image_pull_secrets],
            "tolerations": settings.kubernetes_tolerations,
            "containers": [{
                "name": "analysis", "image": settings.sandbox_image,
                "imagePullPolicy": settings.kubernetes_image_pull_policy,
                "command": ["sleep", str(lifetime)],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {
                    "requests": {"cpu": settings.kubernetes_cpu_request, "memory": settings.kubernetes_memory_request},
                    "limits": {"cpu": settings.kubernetes_cpu_limit, "memory": f"{settings.sandbox_memory_mb}Mi"},
                },
                "volumeMounts": [
                    {"name": "input", "mountPath": "/input/sample.bin", "subPath": relative.as_posix(), "readOnly": True},
                    {"name": "workspace", "mountPath": "/workspace"}, {"name": "tmp", "mountPath": "/tmp"},
                ],
            }],
            "volumes": [
                {"name": "input", "persistentVolumeClaim": {"claimName": settings.kubernetes_pvc_name, "readOnly": True}},
                {"name": "workspace", "emptyDir": {"medium": "Memory", "sizeLimit": "256Mi"}},
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "128Mi"}},
            ],
        }
        if settings.kubernetes_runtime_class_name:
            pod_spec["runtimeClassName"] = settings.kubernetes_runtime_class_name
        metadata = {"name": self.name, "namespace": self.namespace, "labels": labels}
        if settings.kubernetes_worker_pod_uid and settings.kubernetes_worker_pod_name:
            metadata["ownerReferences"] = [{
                "apiVersion": "v1", "kind": "Pod", "name": settings.kubernetes_worker_pod_name,
                "uid": settings.kubernetes_worker_pod_uid,
            }]
        return {
            "apiVersion": "batch/v1", "kind": "Job", "metadata": metadata,
            "spec": {"backoffLimit": 0, "ttlSecondsAfterFinished": settings.kubernetes_job_ttl_seconds,
                     "activeDeadlineSeconds": lifetime + settings.kubernetes_startup_timeout_seconds,
                     "template": {"metadata": {"labels": labels}, "spec": pod_spec}},
        }

    async def __aenter__(self):
        inputs = self.cwd / "input"
        inputs.mkdir(mode=0o755)
        shutil.copyfile(self.sample, inputs / "sample.bin")
        (inputs / "sample.bin").chmod(0o444)
        try:
            await self.kubectl("create", "-f", "-", input_data=json.dumps(self.manifest()).encode())
            deadline = time.monotonic() + self.settings.kubernetes_startup_timeout_seconds
            while time.monotonic() < deadline:
                self.pod_name = await self.running_pod()
                if self.pod_name:
                    return self
                await asyncio.sleep(1)
            raise ProcessError("Kubernetes analysis startup timed out; check image pulls, PVC attachment, scheduling and quotas.")
        except BaseException:
            await self.close()
            raise

    async def collect(self) -> dict:
        output, _ = await self.exec(
            "python3", "-m", "malanalyzer.static_analysis", "/input/sample.bin",
            timeout=self.settings.static_timeout_seconds,
        )
        return json.loads(output)

    async def close(self):
        with contextlib.suppress(ProcessError, TimeoutError, OSError):
            await self.kubectl("delete", "job", self.name, "--ignore-not-found", "--wait=false", timeout=15)

    async def __aexit__(self, *_):
        await self.close()
