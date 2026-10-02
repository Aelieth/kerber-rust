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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    /// MIT `main` (`kdb5_util.c:230-293`): kdb5_util's global options.
    const KDB5_UTIL: &[MitOpt] = &[
        MitOpt::value("-P"),
        MitOpt::value("-d"),
        MitOpt::value("-x"),
        MitOpt::value("-r"),
        MitOpt::value("-k"),
        MitOpt::value("-kv"),
        MitOpt::value("-M"),
        MitOpt::value("-sf"),
        MitOpt::flag("-m"),
    ];

    /// MIT `main` (`ovsec_kadmd.c:364-430`): kadmind's options.
    const KADMIND: &[MitOpt] = &[
        MitOpt::value("-x"),
        MitOpt::value("-r"),
        MitOpt::flag("-m"),
        MitOpt::flag("-nofork"),
        MitOpt::flag("-proponly"),
        MitOpt::value("-port"),
        MitOpt::value("-P"),
        MitOpt::flag("-W"),
        MitOpt::value("-p"),
        MitOpt::value("-F"),
        MitOpt::value("-K"),
        MitOpt::value("-k"),
    ];

    #[test]
    fn kdb5_util_globals_after_the_command() {
        let a = MitArgs::parse(
            &s(&["create", "-s", "-r", "EXAMPLE.COM", "-P", "pw"]),
            KDB5_UTIL,
            Placement::Anywhere,
        )
        .unwrap();
        assert_eq!(a.operands, ["create", "-s"]);
        assert_eq!(a.value("-r"), Some("EXAMPLE.COM"));
        assert_eq!(a.value("-P"), Some("pw"));
        assert!(!a.flag("-m"));
    }

    #[test]
    fn kdb5_util_globals_before_and_between() {
        let a = MitArgs::parse(
            &s(&[
                "-sf", "/k/stash", "-m", "dump", "-verbose", "-d", "/k/db", "out.dump",
            ]),
            KDB5_UTIL,
            Placement::Anywhere,
        )
        .unwrap();
        assert_eq!(a.operands, ["dump", "-verbose", "out.dump"]);
        assert_eq!(a.value("-sf"), Some("/k/stash"));
        assert_eq!(a.value("-d"), Some("/k/db"));
        assert!(a.flag("-m"));
    }

    #[test]
    fn last_value_wins_and_x_accumulates() {
        let a = MitArgs::parse(
            &s(&[
                "-r", "A.TEST", "-x", "one", "stash", "-r", "B.TEST", "-x", "two",
            ]),
            KDB5_UTIL,
            Placement::Anywhere,
        )
        .unwrap();
        assert_eq!(a.value("-r"), Some("B.TEST"));
        assert_eq!(a.values("-x"), ["one", "two"]);
        assert_eq!(a.operands, ["stash"]);
    }

    #[test]
    fn a_value_is_the_next_argument_whatever_it_looks_like() {
        let a =
            MitArgs::parse(&s(&["-P", "-s", "create"]), KDB5_UTIL, Placement::Anywhere).unwrap();
        assert_eq!(a.value("-P"), Some("-s"));
        assert_eq!(a.operands, ["create"]);
    }

    #[test]
    fn exact_spelling_only() {
        let a = MitArgs::parse(
            &s(&["-rEXAMPLE.COM", "-ms", "--", "-s"]),
            KDB5_UTIL,
            Placement::Anywhere,
        )
        .unwrap();
        assert_eq!(a.opts, []);
        assert_eq!(a.operands, ["-rEXAMPLE.COM", "-ms", "--", "-s"]);
    }

    #[test]
    fn missing_value_is_an_error() {
        let e = MitArgs::parse(&s(&["create", "-s", "-P"]), KDB5_UTIL, Placement::Anywhere)
            .unwrap_err();
        assert_eq!(e, ArgError::MissingValue("-P"));
        assert_eq!(e.to_string(), "option -P requires an argument");
    }

    #[test]
    fn kadmind_options_stop_at_the_first_unknown() {
        let a = MitArgs::parse(
            &s(&["-nofork", "-port", "7749", "-r", "EXAMPLE.COM", "-W"]),
            KADMIND,
            Placement::Leading,
        )
        .unwrap();
        assert!(a.flag("-nofork") && a.flag("-W"));
        assert_eq!(a.value("-port"), Some("7749"));
        assert_eq!(a.value("-r"), Some("EXAMPLE.COM"));
        assert_eq!(a.operands, [] as [String; 0]);
        let a = MitArgs::parse(
            &s(&["-nofork", "extra", "-r", "R"]),
            KADMIND,
            Placement::Leading,
        )
        .unwrap();
        assert_eq!(a.opts, [("-nofork", None)]);
        assert_eq!(a.operands, ["extra", "-r", "R"]);
    }
}
