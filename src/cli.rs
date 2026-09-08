//! Command line interface.
//!
//! The sensor follows a DXL fabric the way `tail -f` follows a file: one record
//! per line on stdout, forever, until interrupted. Everything that is not a
//! record - progress, warnings, connection trouble - goes to stderr, so the
//! stream survives a pipe:
//!
//! ```text
//! opendxl-siem-sensor -c dxlclient.config | grep 'Legacy Cipher'
//! opendxl-siem-sensor -f json | jq 'select(.severity_id >= 4)'
//! ```
//!
//! Parsed by hand on purpose: the sensor watches a security fabric, and six
//! flags are not worth another dependency tree in that position.

use std::fmt;

pub const USAGE: &str = "\
opendxl-siem-sensor - follow a DXL fabric and write normalised records

USAGE:
    opendxl-siem-sensor [OPTIONS] [CONFIG]

    CONFIG is the dxlclient.config to connect with. It can also be given with
    -c/--config or in the DXL_CONFIG environment variable, in that order of
    precedence.

OPTIONS:
    -c, --config <FILE>   Client configuration file
    -f, --format <FMT>    Output format for each record (default: cef)
                            cef     ArcSight CEF, one line per record
                            json    OCSF as single-line JSON, for jq
                            plain   human readable: time, severity, event, who
    -o, --only <WHAT>     Which records to write (default: all)
                            all         fabric events and detections
                            events      fabric events only
                            detections  detections only
    -q, --quiet           Do not write progress to stderr (errors still appear)
    -h, --help            Print this help
    -V, --version         Print the version

Records go to stdout, diagnostics to stderr, so the output can be piped.
Log verbosity follows RUST_LOG (see env_logger); --quiet raises the floor to
warnings regardless.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Cef,
    Json,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Only {
    All,
    Events,
    Detections,
}

/// What produced a record. `Only` filters on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Event,
    Detection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub config: Option<String>,
    pub format: Format,
    pub only: Only,
    pub quiet: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config: None,
            format: Format::Cef,
            only: Only::All,
            quiet: false,
        }
    }
}

/// Why parsing stopped. `Help` and `Version` are not failures; the caller
/// prints them and exits 0.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    Help,
    Version,
    Error(String),
}

impl fmt::Display for ParseOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseOutcome::Help => f.write_str(USAGE),
            ParseOutcome::Version => write!(
                f,
                "opendxl-siem-sensor {}",
                option_env!("CARGO_PKG_VERSION").unwrap_or("unknown")
            ),
            ParseOutcome::Error(message) => f.write_str(message),
        }
    }
}

impl Cli {
    pub fn from_env() -> Result<Self, ParseOutcome> {
        Self::parse(std::env::args().skip(1))
    }

    pub fn parse<I, S>(args: I) -> Result<Self, ParseOutcome>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut cli = Cli::default();
        let mut positional: Option<String> = None;
        let mut args = args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => return Err(ParseOutcome::Help),
                "-V" | "--version" => return Err(ParseOutcome::Version),
                "-q" | "--quiet" => cli.quiet = true,
                "-c" | "--config" => cli.config = Some(value(&arg, &mut args)?),
                "-f" | "--format" => cli.format = parse_format(&value(&arg, &mut args)?)?,
                "-o" | "--only" => cli.only = parse_only(&value(&arg, &mut args)?)?,
                other if other.starts_with("--") && other.contains('=') => {
                    let (name, val) = other.split_once('=').expect("contains checked above");
                    match name {
                        "--config" => cli.config = Some(val.to_string()),
                        "--format" => cli.format = parse_format(val)?,
                        "--only" => cli.only = parse_only(val)?,
                        _ => return Err(unknown(name)),
                    }
                }
                other if other.starts_with('-') && other.len() > 1 => return Err(unknown(other)),
                other => {
                    if positional.is_some() {
                        return Err(ParseOutcome::Error(format!(
                            "unexpected extra argument: {other}"
                        )));
                    }
                    positional = Some(other.to_string());
                }
            }
        }

        // -c wins over the positional, which wins over the environment. Reading
        // the variable here rather than in main keeps the precedence in one place.
        if cli.config.is_none() {
            cli.config = positional.or_else(|| std::env::var("DXL_CONFIG").ok());
        }
        Ok(cli)
    }

    /// Whether a record of this kind should be written.
    pub fn wants(&self, kind: Kind) -> bool {
        matches!(
            (self.only, kind),
            (Only::All, _) | (Only::Events, Kind::Event) | (Only::Detections, Kind::Detection)
        )
    }
}

fn value<I: Iterator<Item = String>>(flag: &str, args: &mut I) -> Result<String, ParseOutcome> {
    args.next()
        .ok_or_else(|| ParseOutcome::Error(format!("{flag} needs a value")))
}

fn unknown(flag: &str) -> ParseOutcome {
    ParseOutcome::Error(format!("unknown option: {flag}"))
}

fn parse_format(value: &str) -> Result<Format, ParseOutcome> {
    match value {
        "cef" => Ok(Format::Cef),
        "json" => Ok(Format::Json),
        "plain" => Ok(Format::Plain),
        other => Err(ParseOutcome::Error(format!(
            "unknown format: {other} (expected cef, json or plain)"
        ))),
    }
}

fn parse_only(value: &str) -> Result<Only, ParseOutcome> {
    match value {
        "all" => Ok(Only::All),
        "events" => Ok(Only::Events),
        "detections" => Ok(Only::Detections),
        other => Err(ParseOutcome::Error(format!(
            "unknown selection: {other} (expected all, events or detections)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, ParseOutcome> {
        Cli::parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_are_cef_and_everything() {
        let cli = parse(&[]).expect("no arguments is valid");
        assert_eq!(cli.format, Format::Cef);
        assert_eq!(cli.only, Only::All);
        assert!(!cli.quiet);
    }

    #[test]
    fn a_positional_argument_is_the_config() {
        let cli = parse(&["/etc/dxlclient.config"]).expect("positional config");
        assert_eq!(cli.config.as_deref(), Some("/etc/dxlclient.config"));
    }

    #[test]
    fn the_config_flag_wins_over_the_positional() {
        let cli = parse(&["positional.config", "-c", "flag.config"]).expect("both given");
        assert_eq!(cli.config.as_deref(), Some("flag.config"));
    }

    #[test]
    fn long_options_accept_an_equals_sign() {
        let cli = parse(&["--format=json", "--only=detections"]).expect("equals form");
        assert_eq!(cli.format, Format::Json);
        assert_eq!(cli.only, Only::Detections);
    }

    #[test]
    fn help_and_version_are_not_failures() {
        assert_eq!(parse(&["--help"]).unwrap_err(), ParseOutcome::Help);
        assert_eq!(parse(&["-V"]).unwrap_err(), ParseOutcome::Version);
    }

    #[test]
    fn unknown_options_and_values_are_reported_by_name() {
        let err = parse(&["--nope"]).unwrap_err();
        assert!(matches!(&err, ParseOutcome::Error(m) if m.contains("--nope")));

        let err = parse(&["--format", "yaml"]).unwrap_err();
        assert!(matches!(&err, ParseOutcome::Error(m) if m.contains("yaml")));

        let err = parse(&["--config"]).unwrap_err();
        assert!(matches!(&err, ParseOutcome::Error(m) if m.contains("needs a value")));
    }

    #[test]
    fn a_second_positional_is_a_mistake_worth_reporting() {
        let err = parse(&["one.config", "two.config"]).unwrap_err();
        assert!(matches!(&err, ParseOutcome::Error(m) if m.contains("two.config")));
    }

    #[test]
    fn only_filters_by_kind() {
        let all = parse(&[]).unwrap();
        assert!(all.wants(Kind::Event) && all.wants(Kind::Detection));

        let detections = parse(&["--only", "detections"]).unwrap();
        assert!(!detections.wants(Kind::Event));
        assert!(detections.wants(Kind::Detection));

        let events = parse(&["--only", "events"]).unwrap();
        assert!(events.wants(Kind::Event));
        assert!(!events.wants(Kind::Detection));
    }
}
