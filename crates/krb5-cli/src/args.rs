#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MitOpt {
    pub name: &'static str,
    pub takes_value: bool,
}

impl MitOpt {
    #[must_use]
    pub const fn flag(name: &'static str) -> Self {
        Self {
            name,
            takes_value: false,
        }
    }

    #[must_use]
    pub const fn value(name: &'static str) -> Self {
        Self {
            name,
            takes_value: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// MIT: `main` (kadmin/cli/ss_wrapper.c:41-77)
pub enum Placement {
    Anywhere,
    Leading,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MitArgs {
    pub opts: Vec<(&'static str, Option<String>)>,
    pub operands: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
// MIT: `ARG_VAL` (kadmin/dbutil/kdb5_util.c:160-160)
pub enum ArgError {
    #[error("option {0} requires an argument")]
    MissingValue(&'static str),
}

impl MitArgs {
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

    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.opts.iter().any(|(n, _)| *n == name)
    }

    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    #[must_use]
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(n, _)| *n == name)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }
}
