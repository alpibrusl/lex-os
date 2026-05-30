# lex-os — trust grant for the manifesto full-chain orchestrator
#
# maps the 8-effect signature of `run_parallel` from orchestrator.lex
# to the lex-os trust lattice:
#
#   [env]        — reads process env; no OS boundary (in-process)
#   [concurrent] — actor scheduling; no OS boundary
#   [io]         — stdout; no OS boundary
#   [time]       — wall clock read; no OS boundary
#   [sql]        — SQLite writes  → filesystem: Low
#   [net]        — HTTP calls     → network:    Mid
#   [proc]       — lex check sub  → exec:       Low
#   [fs_write]   — report + tmp   → filesystem: Mid
#
# filesystem is the higher of sql (Low) and fs_write (Mid) → Mid.
# The implied isolation floor for exec:Low is Gvisor (not a microVM).
#
# The narrowing check — `narrow(orchestrator_grant(), admin_grant())`
# — is pure and runs at `lex check` time via the examples {} block.
# The widening attempt — `narrow(orchestrator_grant(), widened_grant())`
# — is also verified to return Err.

import "./manifest" as m

# The orchestrator needs network and limited exec; no reason for Full
# authority on any axis.
fn orchestrator_grant() -> m.Grant
  examples {
    orchestrator_grant() => { filesystem: m.Mid, network: m.Mid, exec: m.Low }
  }
{
  { filesystem: m.Mid, network: m.Mid, exec: m.Low }
}

# A hypothetical admin/parent grant: the orchestrator runs inside it.
fn admin_grant() -> m.Grant
  examples {
    admin_grant() => { filesystem: m.Full, network: m.Full, exec: m.Full }
  }
{
  { filesystem: m.Full, network: m.Full, exec: m.Full }
}

# A widened grant that attempts to escalate exec to Full. narrow()
# rejects it — child must not exceed parent on any axis, and Gvisor
# (exec:Low) is already sufficient for spawning `lex check`.
fn widened_grant() -> m.Grant
  examples {
    widened_grant() => { filesystem: m.Mid, network: m.Mid, exec: m.Full }
  }
{
  { filesystem: m.Mid, network: m.Mid, exec: m.Full }
}

# Narrowing succeeds: orchestrator fits inside admin.
fn orchestrator_narrows_admin() -> Result[m.Grant, Str]
  examples {
    orchestrator_narrows_admin() => Ok({ filesystem: m.Mid, network: m.Mid, exec: m.Low })
  }
{
  m.narrow(admin_grant(), orchestrator_grant())
}

# Widening is rejected: exec:Full > exec:Low; the type system refuses.
fn widened_is_rejected() -> Result[m.Grant, Str]
  examples {
    widened_is_rejected() => Err("trust widening rejected: child must narrow parent")
  }
{
  m.narrow(orchestrator_grant(), widened_grant())
}

# Isolation floor implied by the orchestrator's grant: exec:Low → Gvisor.
# A microVM is NOT required because exec is Low, not Full.
fn orchestrator_floor() -> m.IsolationFloor
  examples {
    orchestrator_floor() => m.Gvisor
  }
{
  m.implied_floor(orchestrator_grant())
}
