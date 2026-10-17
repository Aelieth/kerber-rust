//! Option tables matched by exact spelling: the hand-written argv loops of MIT `kdb5_util`
//! (`kadmin/dbutil/kdb5_util.c` `main`) and `kadmind` (`kadmin/server/ovsec_kadmd.c` `main`),
//! which are not getopt: no clustering, no attached values, and multi-letter single-dash
//! options such as `-nofork`, `-port` and `-sf`.

/// One option of a tool's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MitOpt {
    /// The whole argument as typed, dash included (`-r`, `-nofork`, `-sf`).
    pub name: &'static str,
    /// Whether the next argument is this option's value.
    pub takes_value: bool,
}

impl MitOpt {
    /// An option that stands alone (`-m`, `-nofork`).
    #[must_use]
    pub const fn flag(name: &'static str) -> Self {
        Self {
            name,
            takes_value: false,
        }
    }

    /// An option whose value is the next argument, whatever it looks like (`-r REALM`,
    /// `-P password`).
    #[must_use]
    pub const fn value(name: &'static str) -> Self {
        Self {
            name,
            takes_value: true,
        }
    }
}

/// Where a tool's options may appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Anywhere: an option is taken wherever it stands and every other argument, in order, is
    /// an operand.
    /// MIT `main` (`kdb5_util.c:228-296`): a global option is consumed wherever it appears;
    /// everything else, the command name first, forms the command's argv.
    Anywhere,
    /// Before the first argument the table does not name; that argument and everything after
    /// it are operands.
    /// MIT `main` (`ovsec_kadmd.c:362-435`): the loop `break`s at the first unknown argument
    /// and anything left is a usage error.
    Leading,
}

/// A command line parsed against a table of [`MitOpt`]s.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MitArgs {
    /// The options found, in command-line order, each with its value.
    pub opts: Vec<(&'static str, Option<String>)>,
    /// The other arguments, in order.
    pub operands: Vec<String>,
}

/// A command line the table does not accept.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    /// A value option was the last argument. MIT prints the tool's usage.
    /// MIT `ARG_VAL` (`kdb5_util.c:160-160`): `usage()` when no argument follows.
    #[error("option {0} requires an argument")]
    MissingValue(&'static str),
}

impl MitArgs {
    /// Split `args` (no argv0) by `table`.
    ///
    /// # Errors
    ///
    /// [`ArgError::MissingValue`] when a value option has nothing after it.
    pub fn parse(
        args: &[String],
        table: &[MitOpt],
        placement: Placement,
    ) -> Result<Self, ArgError> {
        let mut out = Self::default();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let Some(opt) = table.iter().find(|o| o.name == arg) else {
                out.operands.push(arg.clone());
                if placement == Placement::Leading {
                    out.operands.extend(it.cloned());
                    break;
                }
                continue;
            };
            let value = if opt.takes_value {
                Some(it.next().ok_or(ArgError::MissingValue(opt.name))?.clone())
            } else {
                None
            };
            out.opts.push((opt.name, value));
        }
        Ok(out)
    }

    /// Whether option `name` was given.
    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.opts.iter().any(|(n, _)| *n == name)
    }

    /// The value of the last `name`: a repeated option overrides, as each MIT loop assigns.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    /// Every value of `name`, in order (`-x db_arg` accumulates).
    #[must_use]
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(n, _)| *n == name)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }
}
