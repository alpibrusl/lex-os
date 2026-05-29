//! External budget ledger (design doc §5.2). Owned by the supervisor,
//! never the agent. Tracks consumption against the manifest's hard
//! ceilings and survives reprovisioning — a fresh box does not get a
//! fresh budget.

use lex_os_manifest::Budget;

/// What a single command costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charge {
    pub commands: u64,
    pub money_cents: u64,
    pub api_calls: u64,
}

/// Running totals against a fixed [`Budget`].
#[derive(Debug, Clone)]
pub struct BudgetLedger {
    budget: Budget,
    started_secs: u64,
    commands: u64,
    money_cents: u64,
    api_calls: u64,
}

impl BudgetLedger {
    pub fn new(budget: Budget, started_secs: u64) -> Self {
        Self {
            budget,
            started_secs,
            commands: 0,
            money_cents: 0,
            api_calls: 0,
        }
    }

    pub fn commands_used(&self) -> u64 {
        self.commands
    }
    pub fn money_used_cents(&self) -> u64 {
        self.money_cents
    }
    pub fn api_calls_used(&self) -> u64 {
        self.api_calls
    }

    pub fn elapsed_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.started_secs)
    }

    /// Has the wall-clock ceiling been reached?
    pub fn wall_clock_exhausted(&self, now_secs: u64) -> bool {
        self.elapsed_secs(now_secs) >= self.budget.wall_clock_secs
    }

    /// Would applying `charge` push any ceiling over? Returns the name
    /// of the first ceiling that would be exceeded, or `None` if the
    /// charge fits. Checked *before* the effect runs.
    pub fn would_exceed(&self, charge: &Charge) -> Option<String> {
        if self.commands + charge.commands > self.budget.max_commands {
            return Some("commands".into());
        }
        if self.money_cents + charge.money_cents > self.budget.max_money_cents {
            return Some("money".into());
        }
        if self.api_calls + charge.api_calls > self.budget.max_api_calls {
            return Some("api_calls".into());
        }
        None
    }

    /// Apply a charge. Callers must check [`Self::would_exceed`] first;
    /// this asserts the invariant in debug builds.
    pub fn charge(&mut self, charge: &Charge) {
        debug_assert!(
            self.would_exceed(charge).is_none(),
            "charge would exceed budget"
        );
        self.commands += charge.commands;
        self.money_cents += charge.money_cents;
        self.api_calls += charge.api_calls;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget {
            wall_clock_secs: 10,
            max_commands: 2,
            max_money_cents: 100,
            max_api_calls: 3,
        }
    }

    #[test]
    fn charges_accumulate() {
        let mut l = BudgetLedger::new(budget(), 0);
        let c = Charge {
            commands: 1,
            money_cents: 40,
            api_calls: 1,
        };
        assert!(l.would_exceed(&c).is_none());
        l.charge(&c);
        assert_eq!(l.commands_used(), 1);
        assert_eq!(l.money_used_cents(), 40);
    }

    #[test]
    fn detects_each_ceiling() {
        let mut l = BudgetLedger::new(budget(), 0);
        l.charge(&Charge {
            commands: 2,
            money_cents: 0,
            api_calls: 0,
        });
        assert_eq!(
            l.would_exceed(&Charge {
                commands: 1,
                money_cents: 0,
                api_calls: 0
            }),
            Some("commands".into())
        );

        let mut l = BudgetLedger::new(budget(), 0);
        assert_eq!(
            l.would_exceed(&Charge {
                commands: 0,
                money_cents: 101,
                api_calls: 0
            }),
            Some("money".into())
        );
        l.charge(&Charge {
            commands: 0,
            money_cents: 0,
            api_calls: 3,
        });
        assert_eq!(
            l.would_exceed(&Charge {
                commands: 0,
                money_cents: 0,
                api_calls: 1
            }),
            Some("api_calls".into())
        );
    }

    #[test]
    fn wall_clock_is_relative_to_start() {
        let l = BudgetLedger::new(budget(), 100);
        assert!(!l.wall_clock_exhausted(105));
        assert_eq!(l.elapsed_secs(105), 5);
        assert!(l.wall_clock_exhausted(110));
    }
}
