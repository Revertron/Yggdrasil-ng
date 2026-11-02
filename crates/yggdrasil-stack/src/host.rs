//! Destination names understood by the stack: IPv6 literals in 200::/7 and
//! node public keys.

use std::fmt;
use std::io;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// Domain suffix that names a node by public key: `<64 hex chars>.pk.ygg`.
pub const KEY_DOMAIN_SUFFIX: &str = ".pk.ygg";

/// A Yggdrasil host: an address, or a node public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Addr(Ipv6Addr),
    Key([u8; 32]),
}

impl FromStr for Host {
    type Err = io::Error;

    /// Accepts `200:1234::1`, `[200:1234::1]`, `<hex key>` or `<hex key>.pk.ygg`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{s:?} is neither a Yggdrasil address nor a public key"),
            )
        };
        let s = s.trim();
        let bare = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
        if let Ok(addr) = bare.parse::<Ipv6Addr>() {
            crate::stack::check_remote(&addr)?;
            return Ok(Host::Addr(addr));
        }
        let lower = s.to_ascii_lowercase();
        let hex_key = lower
            .strip_suffix(KEY_DOMAIN_SUFFIX)
            .unwrap_or(&lower)
            .trim_end_matches('.');
        if hex_key.len() != 64 {
            return Err(invalid());
        }
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_key[2 * i..2 * i + 2], 16).map_err(|_| invalid())?;
        }
        Ok(Host::Key(key))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Addr(a) => write!(f, "{a}"),
            Host::Key(k) => {
                for b in k {
                    write!(f, "{b:02x}")?;
                }
                f.write_str(KEY_DOMAIN_SUFFIX)
            }
        }
    }
}

/// A host and port on the Yggdrasil network, e.g. `[200::1]:80` or
/// `<hex key>.pk.ygg:80`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl FromStr for Target {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, format!("{s:?} is not host:port"));
        let (host, port) = s.trim().rsplit_once(':').ok_or_else(invalid)?;
        let port = port.parse::<u16>().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        // A bare IPv6 address needs brackets to be told apart from the port.
        if !host.starts_with('[') && host.contains(':') {
            return Err(invalid());
        }
        Ok(Target { host: host.parse()?, port })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.host {
            Host::Addr(a) => write!(f, "[{a}]:{}", self.port),
            Host::Key(_) => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "3a8b4c5fb59f439b42b897fe48ac849c90be218c66a21fb49f28499d73b6aece";

    #[test]
    fn parses_hosts() {
        assert_eq!("200::1".parse::<Host>().unwrap(), Host::Addr("200::1".parse().unwrap()));
        assert_eq!("[300::1]".parse::<Host>().unwrap(), Host::Addr("300::1".parse().unwrap()));
        let Host::Key(k) = KEY.parse::<Host>().unwrap() else { panic!() };
        assert_eq!(k[0], 0x3a);
        let upper = format!("{}.PK.YGG", KEY.to_uppercase());
        assert_eq!(upper.parse::<Host>().unwrap(), Host::Key(k));
        assert_eq!(Host::Key(k).to_string(), format!("{KEY}.pk.ygg"));
        assert!("fd00::1".parse::<Host>().is_err());
        assert!("example.com".parse::<Host>().is_err());
        assert!(KEY[..62].parse::<Host>().is_err());
    }

    #[test]
    fn parses_targets() {
        let t: Target = "[200::1]:80".parse().unwrap();
        assert_eq!(t.port, 80);
        assert_eq!(t.to_string(), "[200::1]:80");
        let t: Target = format!("{KEY}.pk.ygg:443").parse().unwrap();
        assert!(matches!(t.host, Host::Key(_)));
        assert_eq!(t.to_string(), format!("{KEY}.pk.ygg:443"));
        assert!("200::1:80".parse::<Target>().is_err());
        assert!("[200::1]:0".parse::<Target>().is_err());
        assert!("[200::1]".parse::<Target>().is_err());
    }
}
