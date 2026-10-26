"""Closed identities for explicit read-only cache outcome recovery."""
from datetime import datetime, timedelta
import hashlib
import json
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .preparation_budget import moment, timestamp, utc_now, PREPARATION_SECONDS


class RecoveryBudget(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    schema_version: Literal[1]
    purpose: Literal['readonly_cache_reconciliation']
    recovery_id: str
    issued_at: str
    deadline_at: str

    @field_validator('schema_version', mode='before')
    @classmethod
    def strict_version(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError('recovery version must be an integer')
        return value

    @field_validator('recovery_id')
    @classmethod
    def identity(cls, value: str) -> str:
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError('recovery identity must be canonical UUID4')
        return value

    @model_validator(mode='after')
    def interval(self):
        if (moment(self.deadline_at) - moment(self.issued_at)).total_seconds() != PREPARATION_SECONDS:
            raise ValueError('recovery budget must be exactly 900 seconds')
        return self


def issue_recovery_budget(*, now: datetime | None = None) -> RecoveryBudget:
    issued = now if now is not None else utc_now()
    return RecoveryBudget(schema_version=1, purpose='readonly_cache_reconciliation',
                          recovery_id=str(uuid4()), issued_at=timestamp(issued),
                          deadline_at=timestamp(issued + timedelta(seconds=PREPARATION_SECONDS)))


class RecoveryGeneration(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    generation_id: str = Field(pattern=r'^[0-9a-f]{64}$')
    manifest_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


class RecoveryTarget(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    operation_id: str
    request_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    attempt: int = Field(ge=1, le=3)
    record_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_job_id: int = Field(gt=0)
    original_job_revision: int = Field(gt=0)
    pointer_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    active: RecoveryGeneration

    @field_validator('operation_id')
    @classmethod
    def identity(cls, value: str) -> str:
        parsed = UUID(value)
        if str(parsed) != value or parsed.variant != 'specified in RFC 4122':
            raise ValueError('target operation must be canonical RFC4122 UUID')
        return value


def recovery_digest(budget: RecoveryBudget, target: RecoveryTarget) -> str:
    document = {'schema_version': 3, 'kind': 'cache_reconcile', 'requested_components': [],
                'reconciliation_budget': budget.model_dump(mode='json'),
                'reconciliation_target': target.model_dump(mode='json')}
    encoded = json.dumps(document, allow_nan=False, ensure_ascii=False,
                         separators=(',', ':'), sort_keys=True).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


class RecoveryResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    kind: Literal['reconciliation']
    active: RecoveryGeneration
    previous_good: RecoveryGeneration | None
    original_operation_id: str
    original_request_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_record_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_workflow_deadline_exceeded: bool
    verified_at: str

    @field_validator('original_operation_id')
    @classmethod
    def identity(cls, value: str) -> str:
        return RecoveryTarget.identity(value)

    @field_validator('verified_at')
    @classmethod
    def proof_time(cls, value: str) -> str:
        moment(value)
        return value


class RecoveryCacheResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    kind: Literal['cache']
    active: RecoveryGeneration
    previous_good: RecoveryGeneration | None
    updated_components: list[str] = Field(max_length=32)

    @field_validator('updated_components')
    @classmethod
    def components(cls, value: list[str]) -> list[str]:
        allowed = {'trivy-db', 'trivy-java-db', 'trivy-checks', 'opengrep-reviewed-rules',
                   'bearer-rules', 'grype-db'}
        if value != sorted(set(value)) or set(value) - allowed:
            raise ValueError('recovery outcome component set is not reviewed')
        return value


class RecoveryIntent(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    original_completed_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_finished_at: str
    cache_result: RecoveryCacheResult
    result: RecoveryResult

    @model_validator(mode='after')
    def consistent(self):
        if (self.original_completed_sha256 != self.result.original_record_sha256
                or self.original_finished_at != self.result.verified_at
                or self.cache_result.active != self.result.active
                or self.cache_result.previous_good != self.result.previous_good):
            raise ValueError('historical recovery intent is inconsistent')
        return self
