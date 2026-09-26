//! Local file-permission posture analysis (Surface C).
//!
//! Pure, platform-independent classification of a path's Unix mode bits into
//! posture issues. It inspects **permission bits only** — it never reads file
//! contents, never executes anything, and never escalates. `mod.rs` supplies the
//! read-only directory walk. Unit tested below.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conf {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub id: String,
    pub sev: Sev,
    pub conf: Conf,
    pub title: String,
    pub desc: String,
    pub remediation: Vec<String>,
    pub evidence: Vec<(String, String)>,
}

impl Issue {
    fn n(id: &str, sev: Sev, conf: Conf, title: &str, desc: &str) -> Self {
        Issue {
            id: id.into(),
            sev,
            conf,
            title: title.into(),
            desc: desc.into(),
            remediation: vec![],
            evidence: vec![],
        }
    }
    fn rem(mut self, s: &[&str]) -> Self {
        self.remediation = s.iter().map(|x| x.to_string()).collect();
        self
    }
    fn ev(mut self, k: &str, v: &str) -> Self {
        self.evidence.push((k.into(), v.into()));
        self
    }
}

/// Classify a filename as a well-known secret/credential artifact by NAME only
/// (contents are never read). Public keys (`.pub`) are excluded.
pub fn sensitive_kind(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if n.ends_with(".pub") {
        return None;
    }
    let ssh_keys = [
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_ecdsa_sk",
        "id_ed25519_sk",
    ];
    if ssh_keys.contains(&n.as_str()) {
        return Some("SSH private key");
    }
    for e in [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"] {
        if n.ends_with(e) {
            return Some("private key / keystore");
        }
    }
    if n == ".netrc" || n == "_netrc" {
        return Some("netrc credentials");
    }
    if n == ".pgpass" {
        return Some("pgpass credentials");
    }
    if n == "credentials" {
        return Some("cloud credentials file");
    }
    if n == ".env" || n.starts_with(".env.") || n.ends_with(".env") {
        return Some("environment/secrets file");
    }
    None
}

/// Classify one path's raw Unix permission bits (`mode`, e.g. 0o644).
pub fn classify(path: &str, name: &str, mode: u32, is_dir: bool) -> Vec<Issue> {
    let mut issues = Vec::new();
    let perms = mode & 0o7777;
    let octal = format!("{:o}", perms & 0o777);
    let world_write = perms & 0o002 != 0;
    let group_write = perms & 0o020 != 0;
    let group_or_other = perms & 0o077 != 0;
    let sticky = perms & 0o1000 != 0;

    if !is_dir {
        if let Some(kind) = sensitive_kind(name) {
            if group_write || world_write {
                issues.push(
                    Issue::n(
                        "FS-SECRET-WRITABLE",
                        Sev::Critical,
                        Conf::High,
                        "Secret file writable by group/other",
                        "A private key or credential file is writable by group or other users, \
                         allowing tampering or key replacement.",
                    )
                    .rem(&["Restrict to owner-only (chmod 600)."])
                    .ev("path", path)
                    .ev("kind", kind)
                    .ev("mode", &octal),
                );
                return issues;
            }
            if group_or_other {
                issues.push(
                    Issue::n(
                        "FS-SECRET-READABLE",
                        Sev::High,
                        Conf::High,
                        "Secret file readable by group/other",
                        "A private key or credential file is readable by users other than the \
                         owner, exposing sensitive material. Tools such as ssh also refuse \
                         over-permissive keys.",
                    )
                    .rem(&["Restrict to owner-only (chmod 600)."])
                    .ev("path", path)
                    .ev("kind", kind)
                    .ev("mode", &octal),
                );
                return issues;
            }
            return issues; // sensitive but owner-only → fine
        }
        if world_write {
            issues.push(
                Issue::n(
                    "FS-FILE-WORLD-WRITABLE",
                    Sev::Medium,
                    Conf::High,
                    "World-writable file",
                    "The file is writable by any user on the system, allowing content tampering.",
                )
                .rem(&["Remove world-write (chmod o-w)."])
                .ev("path", path)
                .ev("mode", &octal),
            );
        }
    } else {
        let lname = name.to_ascii_lowercase();
        if (lname == ".ssh" || lname == ".gnupg") && group_or_other {
            issues.push(
                Issue::n(
                    "FS-SENSITIVE-DIR-PERMS",
                    Sev::Medium,
                    Conf::High,
                    "Sensitive directory accessible by group/other",
                    "A directory holding keys/credentials is accessible by users other than the \
                     owner.",
                )
                .rem(&["Restrict to owner-only (chmod 700)."])
                .ev("path", path)
                .ev("mode", &octal),
            );
        }
        if world_write && !sticky {
            issues.push(
                Issue::n(
                    "FS-DIR-WORLD-WRITABLE",
                    Sev::Medium,
                    Conf::High,
                    "World-writable directory without sticky bit",
                    "The directory is writable by any user and lacks the sticky bit, so others \
                     can rename or delete files within it.",
                )
                .rem(&["Remove world-write (chmod o-w) or set the sticky bit (chmod +t)."])
                .ev("path", path)
                .ev("mode", &octal),
            );
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_names() {
        assert_eq!(sensitive_kind("id_rsa"), Some("SSH private key"));
        assert_eq!(sensitive_kind("id_ed25519"), Some("SSH private key"));
        assert_eq!(sensitive_kind("id_rsa.pub"), None);
        assert_eq!(sensitive_kind("server.pem"), Some("private key / keystore"));
        assert_eq!(sensitive_kind("app.key"), Some("private key / keystore"));
        assert_eq!(sensitive_kind(".netrc"), Some("netrc credentials"));
        assert_eq!(sensitive_kind(".pgpass"), Some("pgpass credentials"));
        assert_eq!(sensitive_kind("credentials"), Some("cloud credentials file"));
        assert_eq!(sensitive_kind(".env"), Some("environment/secrets file"));
        assert_eq!(sensitive_kind(".env.production"), Some("environment/secrets file"));
        assert_eq!(sensitive_kind("notes.txt"), None);
    }

    #[test]
    fn secret_readable_is_high() {
        assert!(classify("/h/.ssh/id_rsa", "id_rsa", 0o644, false)
            .iter()
            .any(|x| x.id == "FS-SECRET-READABLE" && x.sev == Sev::High));
    }

    #[test]
    fn secret_owner_only_is_clean() {
        assert!(classify("/h/.ssh/id_rsa", "id_rsa", 0o600, false).is_empty());
    }

    #[test]
    fn secret_group_writable_is_critical() {
        let i = classify("/h/.aws/credentials", "credentials", 0o660, false);
        assert!(i.iter().any(|x| x.id == "FS-SECRET-WRITABLE" && x.sev == Sev::Critical));
        assert!(!i.iter().any(|x| x.id == "FS-SECRET-READABLE"));
    }

    #[test]
    fn world_writable_file() {
        assert!(classify("/h/data.txt", "data.txt", 0o666, false)
            .iter()
            .any(|x| x.id == "FS-FILE-WORLD-WRITABLE" && x.sev == Sev::Medium));
    }

    #[test]
    fn ssh_dir_loose_perms() {
        assert!(classify("/h/.ssh", ".ssh", 0o755, true)
            .iter()
            .any(|x| x.id == "FS-SENSITIVE-DIR-PERMS"));
    }

    #[test]
    fn world_writable_dir_no_sticky() {
        assert!(classify("/h/shared", "shared", 0o777, true)
            .iter()
            .any(|x| x.id == "FS-DIR-WORLD-WRITABLE"));
    }

    #[test]
    fn world_writable_dir_with_sticky_ok() {
        assert!(!classify("/tmp", "tmp", 0o1777, true)
            .iter()
            .any(|x| x.id == "FS-DIR-WORLD-WRITABLE"));
    }

    #[test]
    fn normal_file_clean() {
        assert!(classify("/h/readme.md", "readme.md", 0o644, false).is_empty());
    }
}
