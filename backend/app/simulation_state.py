from pydantic import BaseModel, Field, field_validator


class SimulationConfig(BaseModel):
    scenario_id: str = "power_grid_ot_pivot"
    attack_intensity: float = Field(5.0, ge=0.0, le=10.0)
    stealth_vector: float = Field(5.0, ge=0.0, le=10.0)
    target_node_ids: list[str] = Field(default_factory=list, max_length=50)
    payload_summary: str = Field(default="", max_length=2000)

    @field_validator("payload_summary")
    @classmethod
    def sanitize_payload_summary(cls, v: str) -> str:
        """Strip control characters that could be used for log injection."""
        # Remove null bytes, CR/LF injection for log hygiene
        return v.replace("\x00", "").replace("\r", "").replace("\n", " ")

import threading
from collections import defaultdict
from contextvars import ContextVar

# Session context variable to track request boundaries
session_id_var: ContextVar[str] = ContextVar("session_id", default="default")

_sessions: dict[str, SimulationConfig] = {}
_sim_lock = threading.RLock()


def get_active_simulation() -> SimulationConfig:
    """Thread-safe read of the active simulation config per-session."""
    sid = session_id_var.get()
    with _sim_lock:
        if sid not in _sessions:
            _sessions[sid] = SimulationConfig()
        return _sessions[sid]


def set_active_simulation(config: SimulationConfig) -> None:
    """Thread-safe write of the active simulation config per-session."""
    sid = session_id_var.get()
    with _sim_lock:
        _sessions[sid] = config
