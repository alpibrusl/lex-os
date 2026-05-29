//! Commands: the typed, bounded primitives the *developer* writes
//! (design doc §9 — "Developer ... make every consequential action a
//! proper bounded command"). Commands hold authority; the agent only
//! requests them.
//!
//! In the full system each command is a Lex effect whose type the
//! checker validates against the grant. Here a [`Command`] is the
//! supervisor-side descriptor of that effect: which trust dimension and
//! level it needs, its reversibility class, and its bounded cost. The
//! Lex package under `manifests/` holds the corresponding source-level
//! command definitions.

use lex_os_manifest::{Dimension, Level, Reversibility};
use std::collections::BTreeMap;

/// A bounded command primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub name: String,
    /// The trust dimension the command's effect touches.
    pub dimension: Dimension,
    /// The minimum trust level required to run it.
    pub required_level: Level,
    /// Its blast radius, enforced structurally.
    pub reversibility: Reversibility,
    /// Bounded cost: money in cents and external API calls. A command's
    /// cost is part of its definition, not something the agent sets.
    pub money_cents: u64,
    pub api_calls: u64,
}

impl Command {
    /// A read/query/draft command: reversible and cheap, free to run
    /// (still logged).
    pub fn reversible_cheap(
        name: impl Into<String>,
        dimension: Dimension,
        required_level: Level,
    ) -> Self {
        Self {
            name: name.into(),
            dimension,
            required_level,
            reversibility: Reversibility::ReversibleCheap,
            money_cents: 0,
            api_calls: 0,
        }
    }

    /// An irreversible-but-bounded command (send email, write a file,
    /// spend ≤ €X): allowed within budget, with explicit bounded cost.
    pub fn irreversible_bounded(
        name: impl Into<String>,
        dimension: Dimension,
        required_level: Level,
        money_cents: u64,
        api_calls: u64,
    ) -> Self {
        Self {
            name: name.into(),
            dimension,
            required_level,
            reversibility: Reversibility::IrreversibleBounded,
            money_cents,
            api_calls,
        }
    }

    /// An irreversible-and-consequential command. Registering one is a
    /// design smell in a no-human system — the supervisor refuses to run
    /// it (there is no approval path). Modelled so the refusal is
    /// testable and the classification is explicit.
    pub fn irreversible_consequential(
        name: impl Into<String>,
        dimension: Dimension,
        required_level: Level,
    ) -> Self {
        Self {
            name: name.into(),
            dimension,
            required_level,
            reversibility: Reversibility::IrreversibleConsequential,
            money_cents: 0,
            api_calls: 0,
        }
    }
}

/// The set of commands available to an agent — the developer-authored
/// vocabulary. A command absent from the registry is unrunnable; this
/// is how "ungranted effects are physically absent" is realised at the
/// command layer (the perimeter enforces the same at the kernel layer).
#[derive(Debug, Clone, Default)]
pub struct CommandRegistry {
    commands: BTreeMap<String, Command>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            commands: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, command: Command) {
        self.commands.insert(command.name.clone(), command);
    }

    pub fn get(&self, name: &str) -> Option<&Command> {
        self.commands.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.commands.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lookup() {
        let mut r = CommandRegistry::new();
        r.register(Command::reversible_cheap(
            "fs.read",
            Dimension::Filesystem,
            Level::ReadOnly,
        ));
        assert_eq!(r.len(), 1);
        assert!(r.get("fs.read").is_some());
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn constructors_set_reversibility() {
        assert_eq!(
            Command::reversible_cheap("a", Dimension::Filesystem, Level::ReadOnly).reversibility,
            Reversibility::ReversibleCheap
        );
        assert_eq!(
            Command::irreversible_bounded("b", Dimension::Network, Level::Allowlist, 10, 1)
                .reversibility,
            Reversibility::IrreversibleBounded
        );
        assert_eq!(
            Command::irreversible_consequential("c", Dimension::Filesystem, Level::ReadWrite)
                .reversibility,
            Reversibility::IrreversibleConsequential
        );
    }
}
