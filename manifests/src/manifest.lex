import "std.result" as result

# The trust manifest, expressed in Lex (design doc §7, §11).
#
# This is the source-level twin of the Rust `lex-os-manifest` crate. The
# trust lattice is the same one the Lex type checker uses for effects;
# here we spell the grant, the narrowing-as-subtyping rule, and the
# reversibility classification as ordinary Lex types and pure functions,
# with `examples {}` blocks that run at `lex check` time.
# A trust level along one dimension. Totally ordered by `rank`; `Off`
# means the effect is physically absent. (`None` is Option's
# constructor in Lex, so the bottom level is spelled `Off`.)
type Level = Off | Low | Mid | Full

fn rank(l :: Level) -> Int
  examples {
    rank(Off) => 0,
    rank(Low) => 1,
    rank(Mid) => 2,
    rank(Full) => 3
  }
{
  match l {
    Off => 0,
    Low => 1,
    Mid => 2,
    Full => 3,
  }
}

# Per-dimension subtyping: `a` grants no more than `b`.
fn level_leq(a :: Level, b :: Level) -> Bool
  examples {
    level_leq(Off, Full) => true,
    level_leq(Full, Off) => false,
    level_leq(Mid, Mid) => true,
    level_leq(Low, Mid) => true
  }
{
  rank(a) <= rank(b)
}

# Least upper bound (join): the higher of two levels.
fn level_join(a :: Level, b :: Level) -> Level
  examples {
    level_join(Off, Full) => Full,
    level_join(Low, Mid) => Mid
  }
{
  if rank(a) >= rank(b) {
    a
  } else {
    b
  }
}

# A capability grant: one level per trust dimension. The product of
# totally-ordered dimensions forms the trust lattice.
type Grant = { filesystem :: Level, network :: Level, exec :: Level }

# Subtyping over the lattice: `child` grants no more authority than
# `parent` on any dimension. This is the narrowing relation.
fn grant_leq(child :: Grant, parent :: Grant) -> Bool
  examples {
    grant_leq({ filesystem: Low, network: Off, exec: Off }, { filesystem: Full, network: Full, exec: Full }) => true,
    grant_leq({ filesystem: Low, network: Full, exec: Off }, { filesystem: Low, network: Off, exec: Off }) => false
  }
{
  level_leq(child.filesystem, parent.filesystem) and level_leq(child.network, parent.network) and level_leq(child.exec, parent.exec)
}

# Narrowing-as-subtyping (design doc §7.1). A child manifest is
# well-formed only if it narrows its parent; any widening is rejected —
# the inheritance equivalent of a type error. Refuse, don't downgrade.
fn narrow(parent :: Grant, child :: Grant) -> Result[Grant, Str]
  examples {
    narrow({ filesystem: Full, network: Full, exec: Full }, { filesystem: Low, network: Off, exec: Off }) => Ok({ filesystem: Low, network: Off, exec: Off }),
    narrow({ filesystem: Low, network: Off, exec: Off }, { filesystem: Low, network: Full, exec: Off }) => Err("trust widening rejected: child must narrow parent")
  }
{
  if grant_leq(child, parent) {
    Ok(child)
  } else {
    Err("trust widening rejected: child must narrow parent")
  }
}

# The reversibility class of a command's effect, sorted by blast radius
# (design doc §6). A structural property of the command.
type Reversibility = ReversibleCheap | IrreversibleBounded | IrreversibleConsequential

fn is_runnable_without_human(r :: Reversibility) -> Bool
  examples {
    is_runnable_without_human(ReversibleCheap) => true,
    is_runnable_without_human(IrreversibleBounded) => true,
    is_runnable_without_human(IrreversibleConsequential) => false
  }
{
  match r {
    IrreversibleConsequential => false,
    _ => true,
  }
}

# Hard, externally-enforced resource bounds (design doc §5.2).
type Budget = { wall_clock_secs :: Int, max_commands :: Int, max_money_cents :: Int, max_api_calls :: Int }

# The complete dispatch: goal + grant + budget. This *is* the safety
# boundary once the agent is launched.
type Manifest = { goal :: Str, grant :: Grant, budget :: Budget }

# The isolation floor a grant implies on its own (design doc §8): any
# authority to execute arbitrary binaries demands at least a kernel
# boundary; full exec demands a microVM.
type IsolationFloor = Namespace | Gvisor | MicroVm

fn implied_floor(g :: Grant) -> IsolationFloor
  examples {
    implied_floor({ filesystem: Mid, network: Off, exec: Off }) => Namespace,
    implied_floor({ filesystem: Full, network: Full, exec: Full }) => MicroVm,
    implied_floor({ filesystem: Off, network: Off, exec: Low }) => Gvisor
  }
{
  match g.exec {
    Off => Namespace,
    Full => MicroVm,
    _ => Gvisor,
  }
}

