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
    uid: [u32; 4],
    gid: [u32; 4],
    supplementary_groups: Vec<u32>,
    cap_inheritable: String,
    cap_permitted: String,
    cap_effective: String,
    cap_bounding: String,
    cap_ambient: String,
    no_new_privs: u8,
    seccomp: u8,
    seccomp_filters: u32,
    tracer_pid: u32,
    lsm_label: String,
    namespaces: BTreeMap<String, String>,
}

impl LinuxSecuritySnapshot {
    pub fn effective_uid(&self) -> u32 {
        self.uid[1]
    }

    pub fn effective_gid(&self) -> u32 {
        self.gid[1]
    }

    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }

    /// Convert a complete kernel observation into the public DDC-OS security
    /// context used for candidate grouping.
    pub fn security_context(&self) -> SecurityContext {
        let mut principal = Vec::new();
        for value in self.uid {
            principal.extend_from_slice(&value.to_le_bytes());
        }
        for value in self.gid {
            principal.extend_from_slice(&value.to_le_bytes());
        }
        principal.extend_from_slice(&(self.supplementary_groups.len() as u64).to_le_bytes());
        for group in &self.supplementary_groups {
            principal.extend_from_slice(&group.to_le_bytes());
        }
        let principal_id = ComputeId::derive("linux-principal-v0.2", &[principal.as_slice()]);

        let mut isolation = Vec::new();
        push_framed(&mut isolation, self.lsm_label.as_bytes());
        isolation.push(self.no_new_privs);
        isolation.push(self.seccomp);
        isolation.extend_from_slice(&self.seccomp_filters.to_le_bytes());
        for (name, target) in &self.namespaces {
            push_framed(&mut isolation, name.as_bytes());
            push_framed(&mut isolation, target.as_bytes());
        }
        let isolation_id =
            ComputeId::derive("linux-isolation-context-v0.2", &[isolation.as_slice()]);

        let authority = AuthoritySet::new([
            format!("linux:cap-inheritable:{}", self.cap_inheritable),
            format!("linux:cap-permitted:{}", self.cap_permitted),
            format!("linux:cap-effective:{}", self.cap_effective),
            format!("linux:cap-bounding:{}", self.cap_bounding),
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

    if snapshot.tracer_pid != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "traced-process-not-eligible",
        ));
    }

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

    let uid = parse_id_quad(required(&fields, "Uid")?, "Uid")?;
    let gid = parse_id_quad(required(&fields, "Gid")?, "Gid")?;
    let supplementary_groups = required(&fields, "Groups")?
        .split_whitespace()
        .map(|value| parse_u32(value, "Groups"))
        .collect::<io::Result<Vec<_>>>()?;

    Ok(LinuxSecuritySnapshot {
        uid,
        gid,
        supplementary_groups,
        cap_inheritable: required(&fields, "CapInh")?.to_owned(),
        cap_permitted: required(&fields, "CapPrm")?.to_owned(),
        cap_effective: required(&fields, "CapEff")?.to_owned(),
        cap_bounding: required(&fields, "CapBnd")?.to_owned(),
        cap_ambient: required(&fields, "CapAmb")?.to_owned(),
        no_new_privs: parse_u8(required(&fields, "NoNewPrivs")?, "NoNewPrivs")?,
        seccomp: parse_u8(required(&fields, "Seccomp")?, "Seccomp")?,
        seccomp_filters: parse_u32(required(&fields, "Seccomp_filters")?, "Seccomp_filters")?,
        tracer_pid: parse_u32(required(&fields, "TracerPid")?, "TracerPid")?,
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

fn parse_id_quad(value: &str, field: &str) -> io::Result<[u32; 4]> {
    let values = value
        .split_whitespace()
        .map(|item| parse_u32(item, field))
        .collect::<io::Result<Vec<_>>>()?;
    if values.len() != 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid-{field}"),
        ));
    }
    Ok([values[0], values[1], values[2], values[3]])
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
TracerPid:\t0\n\
Uid:\t1000\t1001\t1002\t1003\n\
Gid:\t2000\t2001\t2002\t2003\n\
Groups:\t10 20 30\n\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000001\n\
CapEff:\t0000000000000002\n\
CapBnd:\t0000000000000003\n\
CapAmb:\t0000000000000004\n\
NoNewPrivs:\t1\n\
Seccomp:\t2\n\
Seccomp_filters:\t1\n";

    #[test]
    fn parses_complete_subject_and_security_flags() {
        let parsed = parse_status(STATUS).unwrap();
        assert_eq!(parsed.uid, [1000, 1001, 1002, 1003]);
        assert_eq!(parsed.gid, [2000, 2001, 2002, 2003]);
        assert_eq!(parsed.effective_uid(), 1001);
        assert_eq!(parsed.effective_gid(), 2001);
        assert_eq!(parsed.supplementary_groups, vec![10, 20, 30]);
        assert_eq!(parsed.cap_effective, "0000000000000002");
        assert_eq!(parsed.no_new_privs, 1);
        assert_eq!(parsed.seccomp, 2);
        assert_eq!(parsed.seccomp_filters, 1);
    }

    #[test]
    fn missing_security_field_fails_closed() {
        let status = STATUS.replace("CapAmb:\t0000000000000004\n", "");
        let err = parse_status(&status).unwrap_err();
        assert!(err.to_string().contains("missing-CapAmb"));
    }

    #[test]
    fn malformed_identity_quad_fails_closed() {
        let status = STATUS.replace(
            "Uid:\t1000\t1001\t1002\t1003",
            "Uid:\t1000\t1001\t1002",
        );
        let err = parse_status(&status).unwrap_err();
        assert!(err.to_string().contains("invalid-Uid"));
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

    #[test]
    fn filesystem_identity_or_capability_change_changes_security_identity() {
        let mut a = parse_status(STATUS).unwrap();
        a.lsm_label = "same".to_owned();
        a.namespaces.insert("mnt".into(), "mnt:[1]".into());

        let mut fsuid = a.clone();
        fsuid.uid[3] += 1;
        assert_ne!(a.security_context().identity(), fsuid.security_context().identity());

        let mut caps = a.clone();
        caps.cap_bounding = "ffffffffffffffff".to_owned();
        assert_ne!(a.security_context().identity(), caps.security_context().identity());
    }
}
