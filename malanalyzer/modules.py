"""Future family automation contracts. Modules are not loaded/executed by this MVP."""

from typing import Any, Protocol

from pydantic import BaseModel, Field

from malanalyzer.models import IOC


class FamilyMatch(BaseModel):
    family: str
    rule_id: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]


class ExtractionResult(BaseModel):
    family: str
    module_version: str
    config: dict[str, Any]
    iocs: list[IOC]
    limitations: list[str] = Field(default_factory=list)


class ConfigExtractor(Protocol):
    """Implement with a deterministic parser; the sample bytes must never be executed."""

    def extract(self, sample: bytes, match: FamilyMatch) -> ExtractionResult: ...
