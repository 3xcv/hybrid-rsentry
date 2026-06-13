"""
simulate.py — Simulation trigger API.
Returns the CLI command for the requested ransomware family so the operator
can copy-paste it into a terminal, or triggers it as a background subprocess
when the backend is running in a development environment.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/simulate", tags=["simulate"])

_FAMILIES = {
    "lockbit": "simulations.sim_lockbit",
    "akira":   "simulations.sim_akira",
    "qilin":   "simulations.sim_qilin",
    "all":     "simulations.sim_all",
}


class SimulateRequest(BaseModel):
    family: str = "lockbit"
    traversal: str = "dfs"
    max_files: int = 20
    delay: float = 0.05


@router.post("/{family}")
async def trigger_simulation(family: str, req: SimulateRequest):
    """Return the CLI command to run the requested simulation family."""
    key = family.lower()
    if key not in _FAMILIES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown family '{family}'. Valid: {sorted(_FAMILIES)}",
        )
    module = _FAMILIES[key]
    cmd_parts = [
        "python -m", module,
        f"--traversal {req.traversal}",
        f"--max-files {req.max_files}",
        f"--delay {req.delay}",
    ]
    cmd = " ".join(cmd_parts)
    return {
        "family": key,
        "module": module,
        "command": cmd,
        "note": "Run this command from the hybrid-rsentry project root with the venv activated.",
    }


@router.get("")
async def list_families():
    return {"families": sorted(_FAMILIES.keys())}
