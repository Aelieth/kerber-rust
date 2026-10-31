// Break an explicit `[n]`, a SEQUENCE OF element or a 32-bit counter (`include!`).

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Der {
    Prim(u8, Vec<u8>),
    Cons(u8, Vec<Der>),
    Raw(Vec<u8>),
}

pub(crate) fn der_len(out: &mut Vec<u8>, n: usize) {
    if let Ok(short) = u8::try_from(n)
        && short < 0x80
    {
        out.push(short);
        return;
    }
    let b = n.to_be_bytes();
    let skip = b.iter().take_while(|&&x| x == 0).count();
    out.push(0x80 | u8::try_from(b.len() - skip).unwrap_or(0));
    out.extend_from_slice(&b[skip..]);
}

impl Der {
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        match self {
            Der::Prim(tag, content) => {
                out.push(*tag);
                der_len(out, content.len());
                out.extend_from_slice(content);
            }
            Der::Cons(tag, _) => {
                let content = self.content();
                out.push(*tag);
                der_len(out, content.len());
                out.extend_from_slice(&content);
            }
            Der::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    pub(crate) fn tag(&self) -> u8 {
        match self {
            Der::Prim(tag, _) | Der::Cons(tag, _) => *tag,
            Der::Raw(bytes) => bytes.first().copied().unwrap_or(0),
        }
    }

    pub(crate) fn content(&self) -> Vec<u8> {
        match self {
            Der::Prim(_, content) => content.clone(),
            Der::Cons(_, kids) => {
                let mut content = Vec::new();
                for k in kids {
                    k.write(&mut content);
                }
                content
            }
            Der::Raw(_) => Vec::new(),
        }
    }
}

pub(crate) fn der_parse(mut b: &[u8]) -> Option<Vec<Der>> {
    let mut out = Vec::new();
    while let Some((&tag, rest)) = b.split_first() {
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&l0, rest) = rest.split_first()?;
        let (len, rest) = if l0 < 0x80 {
            (usize::from(l0), rest)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |a, &x| (a << 8) | usize::from(x));
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        let (content, rest) = rest.split_at(len);
        out.push(if tag & 0x20 == 0 {
            Der::Prim(tag, content.to_vec())
        } else {
            Der::Cons(tag, der_parse(content)?)
        });
        b = rest;
    }
    Some(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Break {
    Absent,
    Tag,
    Extra,
    Short,
    Prim,
    Content,
    Content2,
    Content3,
    Content4,
}

impl Break {
    pub(crate) const ALL: [Break; 9] = [
        Break::Absent,
        Break::Tag,
        Break::Extra,
        Break::Short,
        Break::Prim,
        Break::Content,
        Break::Content2,
        Break::Content3,
        Break::Content4,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Break::Absent => "absent",
            Break::Tag => "tag",
            Break::Extra => "extra",
            Break::Short => "short",
            Break::Prim => "prim",
            Break::Content => "content",
            Break::Content2 => "content2",
            Break::Content3 => "content3",
            Break::Content4 => "content4",
        }
    }
}

pub(crate) fn retag(d: &Der) -> Der {
    match d {
        Der::Cons(_, kids) => Der::Cons(0x31, kids.clone()),
        other => Der::Prim(0x09, other.content()),
    }
}

pub(crate) fn with_extra(d: &Der) -> Der {
    match d {
        Der::Cons(tag, kids) => {
            let mut kids = kids.clone();
            kids.push(Der::Raw(vec![0x00]));
            Der::Cons(*tag, kids)
        }
        other => {
            let mut content = other.content();
            content.push(0x00);
            Der::Prim(other.tag(), content)
        }
    }
}

pub(crate) fn short(d: &Der) -> Der {
    let content = d.content();
    let mut raw = vec![d.tag()];
    der_len(&mut raw, content.len() + 1);
    raw.extend_from_slice(&content);
    Der::Raw(raw)
}

pub(crate) fn flip(d: &Der) -> Der {
    let content = d.content();
    let mut raw = vec![d.tag() ^ 0x20];
    der_len(&mut raw, content.len());
    raw.extend_from_slice(&content);
    Der::Raw(raw)
}

/// INTEGER: 9 octets, past MIT's eight; `FF 7F FF FF FF` (-2^31-1; an octet drop reads 2^31-1);
/// 6 (`krb5_version` refuses); 2^31 (past int32; msg-type and error-code take it).
/// BOOLEAN: 2 octets. BIT STRING: 8 unused. GeneralizedTime: a fraction (MIT takes 15)
/// or month 13 (`timegm` -> next January). GeneralString: non-ASCII (MIT takes it).
pub(crate) fn bad_content(tag: u8, form: u8) -> Option<Vec<u8>> {
    match (tag, form) {
        (0x01, 0) => Some(vec![0xff, 0x00]),
        (0x02, 0) => Some(vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
        (0x02, 1) => Some(vec![0xff, 0x7f, 0xff, 0xff, 0xff]),
        (0x02, 2) => Some(vec![0x06]),
        (0x02, 3) => Some(vec![0x00, 0x80, 0x00, 0x00, 0x00]),
        (0x03, 0) => Some(vec![0x08, 0, 0, 0, 0]),
        (0x18, 0) => Some(b"20261005120000.5Z".to_vec()),
        (0x18, 1) => Some(b"20261305120000Z".to_vec()),
        (0x1b, 0) => Some(vec![b'u', 0xc3, 0x9f, b'r']),
        _ => None,
    }
}

pub(crate) fn with_bad_content(d: &Der, form: u8) -> Option<Der> {
    match d {
        Der::Prim(tag, _) => bad_content(*tag, form).map(|c| Der::Prim(*tag, c)),
        Der::Cons(tag, kids) => kids.iter().enumerate().find_map(|(i, k)| {
            with_bad_content(k, form).map(|nk| {
                let mut kids = kids.clone();
                kids[i] = nk;
                Der::Cons(*tag, kids)
            })
        }),
        Der::Raw(_) => None,
    }
}

pub(crate) const COUNTER: u32 = 0x0102_0304;

/// MIT's 32-bit edges for a counter: INT32_MIN (an int32 and a seq-number both take it), 2^31 in
pub(crate) const COUNTER_EDGES: [(&str, &[u8]); 3] = [
    ("int32-min", &[0x80, 0x00, 0x00, 0x00]),
    ("int32-wide", &[0x00, 0x80, 0x00, 0x00, 0x00]),
    ("uint32-max", &[0x00, 0xff, 0xff, 0xff, 0xff]),
];

pub(crate) type Path = Vec<usize>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Field,
    Element,
    Counter,
}

pub(crate) fn targets(
    d: &Der,
    path: &mut Path,
    parent_is_seq_of: bool,
    out: &mut Vec<(Path, Target)>,
) {
    if parent_is_seq_of {
        out.push((path.clone(), Target::Element));
    } else if d.tag() & 0xe0 == 0xa0 {
        out.push((path.clone(), Target::Field));
    }
    if *d == Der::Prim(0x02, COUNTER.to_be_bytes().to_vec()) {
        out.push((path.clone(), Target::Counter));
    }
    if let Der::Cons(tag, kids) = d {
        let seq_of =
            *tag == 0x30 && kids.len() >= 2 && kids.iter().all(|k| k.tag() == kids[0].tag());
        for (i, k) in kids.iter().enumerate() {
            path.push(i);
            targets(k, path, seq_of, out);
            path.pop();
        }
    }
}

pub(crate) fn path_name(root: &Der, path: &[usize]) -> String {
    let mut name = format!("{:02x}", root.tag());
    let mut d = root;
    for &i in path {
        if let Der::Cons(_, kids) = d
            && let Some(k) = kids.get(i)
        {
            d = k;
            let _ = write!(name, ".{i}:{:02x}", d.tag());
        }
    }
    name
}

pub(crate) fn edit(d: &Der, path: &[usize], with: Option<&Der>) -> Der {
    let Some((&first, rest)) = path.split_first() else {
        return with.cloned().unwrap_or_else(|| d.clone());
    };
    match d {
        Der::Cons(tag, kids) => {
            let mut out = Vec::with_capacity(kids.len());
            for (i, k) in kids.iter().enumerate() {
                if i != first {
                    out.push(k.clone());
                } else if rest.is_empty() {
                    if let Some(w) = with {
                        out.push(w.clone());
                    }
                } else {
                    out.push(edit(k, rest, with));
                }
            }
            Der::Cons(*tag, out)
        }
        other => other.clone(),
    }
}

pub(crate) fn at<'a>(d: &'a Der, path: &[usize]) -> Option<&'a Der> {
    path.iter().try_fold(d, |d, &i| match d {
        Der::Cons(_, kids) => kids.get(i),
        _ => None,
    })
}

pub(crate) enum Edit {
    Remove,
    Replace(Der),
}

pub(crate) fn broken(target: &Der, kind: Target, b: Break) -> Option<Edit> {
    match kind {
        Target::Field => {
            let Der::Cons(tag, kids) = target else {
                return None;
            };
            let [inner] = kids.as_slice() else {
                return None;
            };
            Some(Edit::Replace(match b {
                Break::Absent => return Some(Edit::Remove),
                Break::Tag => Der::Cons(*tag, vec![retag(inner)]),
                Break::Extra => with_extra(target),
                Break::Short => Der::Cons(*tag, vec![short(inner)]),
                Break::Prim => flip(target),
                Break::Content => Der::Cons(*tag, vec![with_bad_content(inner, 0)?]),
                Break::Content2 => Der::Cons(*tag, vec![with_bad_content(inner, 1)?]),
                Break::Content3 => Der::Cons(*tag, vec![with_bad_content(inner, 2)?]),
                Break::Content4 => Der::Cons(*tag, vec![with_bad_content(inner, 3)?]),
            }))
        }
        Target::Element => Some(Edit::Replace(match b {
            Break::Absent => return None,
            Break::Tag => retag(target),
            Break::Extra => with_extra(target),
            Break::Short => short(target),
            Break::Prim => flip(target),
            Break::Content => with_bad_content(target, 0)?,
            Break::Content2 => with_bad_content(target, 1)?,
            Break::Content3 => with_bad_content(target, 2)?,
            Break::Content4 => with_bad_content(target, 3)?,
        })),
        Target::Counter => None,
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

pub(crate) fn all_breaks(root: &Der) -> Vec<(String, Der)> {
    let mut found = Vec::new();
    targets(root, &mut Vec::new(), false, &mut found);
    let mut out = Vec::new();
    for (path, kind) in found {
        let Some(target) = at(root, &path) else {
            continue;
        };
        let place = path_name(root, &path);
        if kind == Target::Counter {
            for (name, value) in COUNTER_EDGES {
                let with = Der::Prim(0x02, value.to_vec());
                out.push((format!("{place}/{name}"), edit(root, &path, Some(&with))));
            }
            continue;
        }
        for b in Break::ALL {
            match broken(target, kind, b) {
                Some(Edit::Replace(with)) => {
                    out.push((
                        format!("{place}/{}", b.name()),
                        edit(root, &path, Some(&with)),
                    ));
                }
                Some(Edit::Remove) => {
                    out.push((format!("{place}/{}", b.name()), edit(root, &path, None)));
                }
                None => {}
            }
        }
    }
    out
}
