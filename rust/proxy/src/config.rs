use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};

pub const USAGE: &str = "usage: pkgre-proxy [--listen <address>] [--canary-seconds <seconds>] [--readiness-seconds <seconds>]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub listen: SocketAddr,
    pub canary_interval: Duration,
    pub readiness_freshness: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
            canary_interval: Duration::from_secs(60),
            readiness_freshness: Duration::from_secs(180),
        }
    }
}

impl Config {
    /// Parses the complete command-line configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown, missing, malformed, zero, or inconsistent arguments.
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut config = Self::default();
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let argument = argument
                .to_str()
                .with_context(|| format!("argument is not valid UTF-8\n{USAGE}"))?;
            match argument {
                "--listen" => {
                    config.listen = next_value(&mut arguments, argument)?
                        .parse()
                        .with_context(|| format!("invalid --listen address\n{USAGE}"))?;
                }
                "--canary-seconds" => {
                    config.canary_interval = Duration::from_secs(parse_seconds(
                        &next_value(&mut arguments, argument)?,
                        argument,
                    )?);
                }
                "--readiness-seconds" => {
                    config.readiness_freshness = Duration::from_secs(parse_seconds(
                        &next_value(&mut arguments, argument)?,
                        argument,
                    )?);
                }
                "--help" | "-h" => bail!(USAGE),
                value => bail!("unknown argument {value:?}\n{USAGE}"),
            }
        }
        ensure!(
            config.readiness_freshness >= config.canary_interval,
            "--readiness-seconds must be at least --canary-seconds"
        );
        Ok(config)
    }
}

fn next_value(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String> {
    arguments
        .next()
        .with_context(|| format!("missing value for {flag}\n{USAGE}"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("value for {flag} is not valid UTF-8\n{USAGE}"))
}

fn parse_seconds(value: &str, flag: &str) -> Result<u64> {
    let seconds = value
        .parse::<u64>()
        .with_context(|| format!("invalid value for {flag}: {value:?}"))?;
    ensure!(seconds > 0, "{flag} must be greater than zero");
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_and_explicit_values_are_strict() {
        assert_eq!(Config::parse(Vec::new()).unwrap(), Config::default());
        let config = Config::parse(arguments(&[
            "--listen",
            "[::1]:4000",
            "--canary-seconds",
            "20",
            "--readiness-seconds",
            "60",
        ]))
        .unwrap();
        assert_eq!(config.listen, "[::1]:4000".parse().unwrap());
        assert_eq!(config.canary_interval, Duration::from_secs(20));
        assert_eq!(config.readiness_freshness, Duration::from_secs(60));
    }

    #[test]
    fn malformed_or_unsafe_timing_arguments_fail() {
        for values in [
            vec!["--unknown"],
            vec!["--listen"],
            vec!["--listen", "not-an-address"],
            vec!["--canary-seconds", "0"],
            vec!["--canary-seconds", "20", "--readiness-seconds", "10"],
            vec!["--refresh-seconds", "60"],
            vec!["--minimum-refresh-seconds", "60"],
        ] {
            assert!(Config::parse(arguments(&values)).is_err(), "{values:?}");
        }
    }
}
