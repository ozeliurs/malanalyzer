from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IOCType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    OTHER = "other"


class IOC(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ioc: str = Field(min_length=1, max_length=4096)
    type: IOCType
    description: str = Field(min_length=1, max_length=2000)


class AnalysisResult(BaseModel):
    """Only the envelope is fixed; the Markdown's structure is the model's choice."""

    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=2000)
    family: str | None = Field(default=None, max_length=200)
    family_confidence: Literal["unknown", "low", "medium", "high"] = "unknown"
    # Preserve the agent's full 150k-character report and reserve space for backend usage metadata.
    report_markdown: str = Field(min_length=1, max_length=152_000)
    iocs: list[IOC] = Field(default_factory=list, max_length=3000)

    @field_validator("title", "summary", "report_markdown")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class Job(BaseModel):
    id: str
    sha256: str
    filename: str
    size: int
    status: Literal["queued", "running", "completed", "failed"]
    stage: str
    attempts: int
    created_at: datetime
    updated_at: datetime
    error: str | None = None
    report_url: str | None = None
    tool_calls: int = 0
    activity: str | None = None


class ReportSummary(BaseModel):
    id: str
    sha256: str
    filename: str
    size: int
    title: str
    summary: str
    family: str | None
    family_confidence: str
    published_at: datetime
    model: str


class Report(ReportSummary):
    report_markdown: str
    iocs: list[IOC]
