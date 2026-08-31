use ddc_core::{AuthoritySet, ComputeId, SecurityContext};
use std::collections::BTreeMap;
use std::fs::{read_link, read_to_string};
use std::io::{self, Error, ErrorKind};

const REQUIRED_NAMESPACES: [&str; 10] = [
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_for_children",
    "user",
    "uts",
];

/// Opaque snapshot returned only by the Linux observation adapter.
///
/// Fields stay private so callers cannot manufacture a value and present it as
/// a procfs observation. This is defense-in-depth; proposal generation is still
/// non-authoritative until a later DDC admission gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSecuritySnapshot {
    effective_uid: u32,
    effective_gid: u32,
    supplementary_groups: Vec<u32>,
    cap_effective: String,
    cap_permitted: String,
    cap_ambient: String,
    no_new_privs: u8,
    seccomp: u8,
    lsm_label: String,
    namespaces: BTreeMap<String, String>,
}

impl LinuxSecuritySnapshot {
    pub fn effective_uid(&self) -> u32 {
        self.effective_uid
    }

    pub fn effective_gid(&self) -> u32 {
        self.effective_gid
    }

    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }

    /// Convert a complete kernel observation into the public DDC-OS security
    /// context used for candidate grouping.
    pub fn security_context(&self) -> SecurityContext {
        let mut principal = Vec::new();
        principal.extend_from_slice(&self.effective_uid.to_le_bytes());
        principal.extend_from_slice(&self.effective_gid.to_le_bytes());
        principal.extend_from_slice(&(self.supplementary_groups.len() as u64).to_le_bytes());
        for group in &self.supplementary_groups {
            principal.extend_from_slice(&group.to_le_bytes());
        }
        let principal_id = ComputeId::derive("linux-principal-v0.2", &[principal.as_slice()]);

        let mut isolation = Vec::new();
        push_framed(&mut isolation, self.lsm_label.as_bytes());
        isolation.push(self.no_new_privs);
        isolation.push(self.seccomp);
        for (name, target) in &self.namespaces {
            push_framed(&mut isolation, name.as_bytes());
            push_framed(&mut isolation, target.as_bytes());
        }
        let isolation_id =
            ComputeId::derive("linux-isolation-context-v0.2", &[isolation.as_slice()]);

        let authority = AuthoritySet::new([
            format!("linux:cap-effective:{}", self.cap_effective),
            format!("linux:cap-permitted:{}", self.cap_permitted),
            format!("linux:cap-ambient:{}", self.cap_ambient),
        ]);

        SecurityContext::from_trusted_observation(principal_id, isolation_id, authority)
    }
}

/// Read the current process security boundary from procfs only.
///
/// v0.2 is observation-only: this function performs no writes, privilege
/// changes, namespace changes, scheduler changes, or memory-policy changes.
pub fn observe_self_security() -> io::Result<LinuxSecuritySnapshot> {
    let status = read_to_string("/proc/self/status")?;
    let mut snapshot = parse_status(&status)?;

    snapshot.lsm_label = read_to_string("/proc/self/attr/current")?
        .trim_end_matches(|c| c == '\n' || c == '\0')
        .to_owned();
    if snapshot.lsm_label.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "empty-lsm-label"));
    }

    for name in REQUIRED_NAMESPACES {
        let target = read_link(format!("/proc/self/ns/{name}"))?;
        let target = target
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "non-utf8-namespace-target"))?;
        snapshot.namespaces.insert(name.to_owned(), target.to_owned());
    }

    if snapshot.namespaces.len() != REQUIRED_NAMESPACES.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "incomplete-namespace-observation",
        ));
    }

    Ok(snapshot)
}

fn parse_status(status: &str) -> io::Result<LinuxSecuritySnapshot> {
    let mut fields = BTreeMap::<&str, &str>::new();
    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(key, value.trim());
        }
    }

    let effective_uid = parse_effective_id(required(&fields, "Uid")?, "Uid")?;
    let effective_gid = parse_effective_id(required(&fields, "Gid")?, "Gid")?;
    let supplementary_groups = required(&fields, "Groups")?
        .split_whitespace()
        .map(|value| parse_u32(value, "Groups"))
        .collect::<io::Result<Vec<_>>>()?;

    Ok(LinuxSecuritySnapshot {
        effective_uid,
        effective_gid,
        supplementary_groups,
        cap_effective: required(&fields, "CapEff")?.to_owned(),
        cap_permitted: required(&fields, "CapPrm")?.to_owned(),
        cap_ambient: required(&fields, "CapAmb")?.to_owned(),
        no_new_privs: parse_u8(required(&fields, "NoNewPrivs")?, "NoNewPrivs")?,
        seccomp: parse_u8(required(&fields, "Seccomp")?, "Seccomp")?,
        lsm_label: String::new(),
        namespaces: BTreeMap::new(),
    })
}

fn required<'a>(fields: &'a BTreeMap<&str, &str>, key: &str) -> io::Result<&'a str> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, format!("missing-{key}")))
}

fn parse_effective_id(value: &str, field: &str) -> io::Result<u32> {
    let mut values = value.split_whitespace();
    let _real = values.next();
    let effective = values
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, format!("invalid-{field}")))?;
    parse_u32(effective, field)
}

fn parse_u32(value: &str, field: &str) -> io::Result<u32> {
    value
        .parse::<u32>()
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("invalid-{field}")))
}

fn parse_u8(value: &str, field: &str) -> io::Result<u8> {
    value
        .parse::<u8>()
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("invalid-{field}")))
}

fn push_framed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "\
Uid:\t1000\t1001\t1002\t1003\n\
Gid:\t2000\t2001\t2002\t2003\n\
Groups:\t10 20 30\n\
CapPrm:\t0000000000000001\n\
CapEff:\t0000000000000002\n\
CapAmb:\t0000000000000004\n\
NoNewPrivs:\t1\n\
Seccomp:\t2\n";

    #[test]
    fn parses_effective_subject_and_security_flags() {
        let parsed = parse_status(STATUS).unwrap();
        assert_eq!(parsed.effective_uid, 1001);
        assert_eq!(parsed.effective_gid, 2001);
        assert_eq!(parsed.supplementary_groups, vec![10, 20, 30]);
        assert_eq!(parsed.cap_effective, "0000000000000002");
        assert_eq!(parsed.no_new_privs, 1);
        assert_eq!(parsed.seccomp, 2);
    }

    #[test]
    fn missing_security_field_fails_closed() {
        let status = STATUS.replace("CapAmb:\t0000000000000004\n", "");
        let err = parse_status(&status).unwrap_err();
        assert!(err.to_string().contains("missing-CapAmb"));
    }

    #[test]
    fn namespace_or_lsm_change_changes_security_identity() {
        let mut a = parse_status(STATUS).unwrap();
        a.lsm_label = "apparmor-a".to_owned();
        a.namespaces.insert("mnt".into(), "mnt:[1]".into());

        let mut b = a.clone();
        b.namespaces.insert("mnt".into(), "mnt:[2]".into());
        assert_ne!(a.security_context().identity(), b.security_context().identity());

        let mut c = a.clone();
        c.lsm_label = "apparmor-b".to_owned();
        assert_ne!(a.security_context().identity(), c.security_context().identity());
    }
}
