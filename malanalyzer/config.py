from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mistral_api_key: SecretStr = SecretStr("")
    upload_api_key: SecretStr = SecretStr("")
    opencode_model: str = "mistral/mistral-large-4"
    opencode_binary: str = "opencode"
    data_dir: Path = Path("data")
    max_upload_mb: int = Field(default=25, ge=1, le=100)
    analysis_timeout_seconds: int = Field(default=1800, ge=10, le=7200)
    analysis_max_steps: int = Field(default=120, ge=5, le=300)
    analysis_max_tool_calls: int = Field(default=100, ge=5, le=250)
    tool_timeout_seconds: int = Field(default=120, ge=5, le=300)
    sandbox_image: str = "malanalyzer-tools:local"
    docker_binary: str = "docker"
    sandbox_memory_mb: int = Field(default=2048, ge=512, le=8192)
    sandbox_backend: Literal["docker", "kubernetes"] = "docker"
    kubectl_binary: str = "kubectl"
    kubernetes_namespace: str = "default"
    kubernetes_pvc_name: str = ""
    kubernetes_node_name: str = ""
    kubernetes_worker_pod_name: str = ""
    kubernetes_worker_pod_uid: str = ""
    kubernetes_instance: str = "malanalyzer"
    kubernetes_analysis_service_account: str = "default"
    kubernetes_image_pull_secrets: list[str] = Field(default_factory=list)
    kubernetes_image_pull_policy: Literal["Always", "IfNotPresent", "Never"] = "IfNotPresent"
    kubernetes_startup_timeout_seconds: int = Field(default=180, ge=10, le=900)
    kubernetes_job_ttl_seconds: int = Field(default=120, ge=0, le=86400)
    kubernetes_cpu_request: str = "250m"
    kubernetes_cpu_limit: str = "2"
    kubernetes_memory_request: str = "256Mi"
    kubernetes_tolerations: list[dict] = Field(default_factory=list)
    kubernetes_runtime_class_name: str = ""
    static_timeout_seconds: int = Field(default=60, ge=5, le=300)
    worker_concurrency: int = Field(default=1, ge=1, le=8)
    embedded_worker: bool = True
    max_attempts: int = Field(default=2, ge=1, le=5)
    lease_seconds: int = Field(default=90, ge=30)
    poll_seconds: float = Field(default=1, ge=0.05)

    @property
    def root(self) -> Path:
        return self.data_dir.resolve()

    def prepare(self) -> None:
        for name in ("samples", "runs", "incoming", "sessions"):
            (self.root / name).mkdir(parents=True, exist_ok=True, mode=0o700)
