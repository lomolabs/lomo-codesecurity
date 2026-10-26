"""Server-issued persisted preparation identity and decreasing execution bounds."""
from datetime import datetime, timedelta, timezone
import time
import math
from typing import Callable, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

PREPARATION_SECONDS = 900
PLATFORM_PREPARATION_SECONDS = {"mac": 1200, "linux": 3120, "windows": 4680}
LEGACY_V3_PREPARATION_SECONDS = {1200, 2400, 3600}
MIN_DISPATCH_SECONDS = 0.001


class PreparationDeadlineExceeded(RuntimeError):
    """No preparation work may be dispatched after the owned group deadline."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError('preparation timestamp must be UTC')
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def moment(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('preparation timestamp must be canonical UTC')
    parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    if timestamp(parsed) != value:
        raise ValueError('preparation timestamp must be canonical UTC')
    return parsed


class PreparationBudget(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    schema_version: Literal[1, 2, 3, 4]
    preparation_id: str
    issued_at: str
    deadline_at: str

    @field_validator('schema_version', mode='before')
    @classmethod
    def strict_version(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError('preparation schema version must be an integer')
        return value

    @field_validator('preparation_id')
    @classmethod
    def identity(cls, value: str) -> str:
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError('preparation identity must be canonical UUID4')
        return value

    @model_validator(mode='after')
    def exact_interval(self) -> 'PreparationBudget':
        seconds = (moment(self.deadline_at) - moment(self.issued_at)).total_seconds()
        allowed = {1: {PREPARATION_SECONDS}, 2: {1800, 2700},
                   3: LEGACY_V3_PREPARATION_SECONDS, 4: {3120, 4680}}[self.schema_version]
        if seconds not in allowed:
            raise ValueError('preparation interval does not match its versioned platform budget')
        return self


def issue_budget(*, now: datetime | None = None, platform: str = "mac") -> PreparationBudget:
    """Only the API command owner calls this; continuation/retry never does."""
    if platform not in PLATFORM_PREPARATION_SECONDS:
        raise ValueError("unsupported preparation platform")
    seconds = PLATFORM_PREPARATION_SECONDS[platform]
    issued = now if now is not None else utc_now()
    return PreparationBudget(schema_version=3 if platform == "mac" else 4,
                             preparation_id=str(uuid4()),
                             issued_at=timestamp(issued),
                             deadline_at=timestamp(issued + timedelta(seconds=seconds)))


def budget_remaining(budget: PreparationBudget, *, now: datetime | None = None,
                     high_water: datetime | None = None) -> float:
    current = now if now is not None else utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if high_water is not None and high_water.tzinfo is None:
        high_water = high_water.replace(tzinfo=timezone.utc)
    if current < moment(budget.issued_at) or (high_water is not None and current < high_water):
        raise PreparationDeadlineExceeded('preparation clock moved backwards')
    remaining = (moment(budget.deadline_at) - current).total_seconds()
    if remaining <= MIN_DISPATCH_SECONDS:
        raise PreparationDeadlineExceeded('scanner preparation deadline exceeded')
    return remaining


class PreparationClock:
    """Recover from persisted UTC once, then take the stricter wall/monotonic bound."""
    def __init__(self, budget: PreparationBudget, *, now: Callable[[], datetime] = utc_now,
                 monotonic: Callable[[], float] = time.monotonic,
                 high_water: datetime | None = None):
        self.budget, self.now, self.monotonic = budget, now, monotonic
        self.high_water = high_water or moment(budget.issued_at)
        current = now()
        self.deadline_monotonic = monotonic() + budget_remaining(budget, now=current, high_water=self.high_water)
        self.high_water = current

    def remaining(self, local_bound: float | None = None) -> float:
        current = self.now()
        wall = budget_remaining(self.budget, now=current, high_water=self.high_water)
        self.high_water = current
        monotonic_now = self.monotonic()
        # A forward wall-clock step must shorten subsequent native/SQL
        # absolute deadlines, not only the current checkpoint result.
        self.deadline_monotonic = min(self.deadline_monotonic, monotonic_now + wall)
        remaining = self.deadline_monotonic - monotonic_now
        if local_bound is not None:
            if isinstance(local_bound, bool) or not math.isfinite(local_bound) or local_bound <= 0:
                raise ValueError('local preparation bound must be positive')
            remaining = min(remaining, local_bound)
        if remaining <= MIN_DISPATCH_SECONDS:
            raise PreparationDeadlineExceeded('scanner preparation deadline exceeded')
        return remaining
