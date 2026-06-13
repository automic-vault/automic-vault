use std::borrow::Cow;
use std::io::IsTerminal;

use super::*;

pub(crate) fn print_i_usage(program: &str) {
    println!(
        "Usage: {program} [-f | --force] <package|brew:formula|cask:cask|isotope:name|npm:package|pip:package>..."
    );
    println!();
    println!(
        "Installs self-contained packages under {}.",
        opt_pkg_root().display()
    );
}

pub(crate) fn print_uninstall_usage(program: &str) {
    println!(
        "Usage: {program} <package|brew:formula|cask:cask|isotope:name|npm:package|pip:package>..."
    );
    println!();
    println!(
        "Removes installed packages from {}.",
        opt_pkg_root().display()
    );
}

pub(crate) fn print_outdated_usage(program: &str) {
    println!(
        "Usage: {program} [package|brew:formula|cask:cask|isotope:name|npm:package|pip:package]..."
    );
    println!();
    println!("Lists installed packages with newer versions available.");
}

pub(crate) fn print_update_usage(program: &str) {
    println!(
        "Usage: {program} [package|brew:formula|cask:cask|isotope:name|npm:package|pip:package]..."
    );
    println!();
    println!("Reinstalls installed packages with newer versions available.");
}

pub(crate) fn print_list_usage(program: &str) {
    println!(
        "Usage: {program} [package|brew:formula|cask:cask|isotope:name|npm:package|pip:package]..."
    );
    println!();
    println!("Lists installed packages with their versions.");
}

pub(crate) fn print_info_usage(program: &str) {
    println!(
        "Usage: {program} <package|brew:formula|cask:cask|isotope:name|npm:package|pip:package>"
    );
    println!();
    println!("Shows package metadata, install status, and update status.");
}

pub(crate) fn print_search_usage(program: &str) {
    println!("Usage: {program} <query>");
    println!();
    println!("Searches available packages.");
}

pub(crate) fn print_secret_scanner_usage(program: &str) {
    println!(
        "Usage: {program} [--path <path>] [--skip <path>]... [--isotopes-only] [--json | --jsonl]"
    );
    println!();
    println!("Scans isotope detectors and likely local secret files for plaintext credentials.");
}

pub(crate) fn print_trace_usage(program: &str) {
    println!("Usage: {program} [--agent codex|claude] [--json] <shell-one-liner>");
    println!();
    println!("Asks a local agent to statically trace likely file-changing steps.");
}

pub(crate) fn print_serve_usage(program: &str) {
    println!("Usage: {program}");
    println!();
    println!("Starts the local Nucleus protocol daemon.");
}

pub(crate) fn print_open_usage(program: &str) {
    println!("Usage: {program}");
    println!();
    println!("Opens Automic Vault.app.");
}

pub(crate) fn print_pkg_usage(program: &str) {
    HelpScreen::new(program, terminal_columns(), stdout_supports_ansi()).print();
}

#[derive(Copy, Clone)]
enum HelpStyle {
    Primary,
    Red,
    Dim,
}

struct HelpFragment<'a> {
    style: HelpStyle,
    text: Cow<'a, str>,
}

struct HelpLine<'a> {
    fragments: Vec<HelpFragment<'a>>,
}

struct HelpScreen<'a> {
    program: &'a str,
    columns: usize,
    color: bool,
}

impl<'a> HelpLine<'a> {
    fn plain(text: &'a str) -> Self {
        Self {
            fragments: vec![HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed(text),
            }],
        }
    }

    fn fragments(fragments: Vec<HelpFragment<'a>>) -> Self {
        Self { fragments }
    }

    fn render(&self, color: bool) -> String {
        let mut line = String::new();
        for fragment in &self.fragments {
            line.push_str(&paint(&fragment.text, fragment.style, color));
        }
        line
    }

    fn width(&self) -> usize {
        self.fragments
            .iter()
            .map(|fragment| fragment.text.chars().count())
            .sum()
    }
}

impl<'a> HelpScreen<'a> {
    const COMMAND_PANE_WIDTH: usize = 78;
    const DESC_COLUMN: usize = 21;
    const SECTION_MARKER: &'static str = "▪";
    const LEGEND_COLUMN: usize = Self::COMMAND_PANE_WIDTH + 2;
    const LEGEND_MIN_COLUMNS: usize = Self::LEGEND_COLUMN + 32;

    fn new(program: &'a str, columns: usize, color: bool) -> Self {
        Self {
            program,
            columns,
            color,
        }
    }

    fn print(&self) {
        let show_legend = self.columns >= Self::LEGEND_MIN_COLUMNS;

        println!("{}", self.top_rule());
        println!(
            "{}",
            HelpLine::fragments(vec![
                HelpFragment {
                    style: HelpStyle::Red,
                    text: Cow::Borrowed("AUTOMIC VAULT  "),
                },
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed("Secure package installs  "),
                },
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed("Controlled execution  "),
                },
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed("Approved secrets"),
                },
            ])
            .render(self.color)
        );
        println!();
        println!(
            "{}",
            HelpLine::fragments(vec![HelpFragment {
                style: HelpStyle::Dim,
                text: Cow::Borrowed("USAGE"),
            }])
            .render(self.color)
        );
        println!("{}", self.usage_line());
        println!();

        let legend = if show_legend {
            self.legend_lines()
        } else {
            Vec::new()
        };
        for (index, line) in self.command_lines().iter().enumerate() {
            self.print_with_legend(line, legend.get(index));
        }

        println!();
        println!("{}", self.rule_with_star());
        println!(
            "{}",
            HelpLine::fragments(vec![
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed("TYPE "),
                },
                HelpFragment {
                    style: HelpStyle::Primary,
                    text: Cow::Borrowed(self.program),
                },
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed(" <subcommand> --help FOR DETAILS ON A COMMAND."),
                },
            ])
            .render(self.color)
        );
        println!();
    }

    fn command_lines(&self) -> Vec<HelpLine<'static>> {
        vec![
            section_line("PACKAGE SYSTEM"),
            command_line("install", Some("i"), "Install a self-contained package."),
            command_line("info", None, "Show package metadata and local status."),
            command_line("search", None, "Search available packages."),
            command_line(
                "list",
                Some("ls"),
                "List installed packages with their versions.",
            ),
            command_line(
                "outdated",
                None,
                "List installed packages with updates available.",
            ),
            command_line(
                "update",
                Some("up"),
                "Reinstall installed packages with updates available.",
            ),
            command_line("uninstall", Some("rm"), "Remove an installed package."),
            HelpLine::plain(""),
            section_line("ACCESS CONTROL"),
            command_line(
                "scan",
                None,
                "Find plaintext credentials visible to agents.",
            ),
            command_line("inject", None, "Inject approved secrets into a process."),
            command_line(
                "save",
                None,
                "Store a secret in the Automic Vault keychain.",
            ),
            command_line(
                "credential-helper",
                None,
                "Run an approved credential helper adapter.",
            ),
            command_line("dotenv", None, "Load encrypted dotenv files with approval."),
            command_line("transfer", None, "Transfer vaulted keys to another Mac."),
            HelpLine::plain(""),
            section_line("EXECUTION CONTROL"),
            command_line(
                "contain",
                None,
                "Run agents with approval gates for all commands.",
            ),
            command_line(
                "trace",
                None,
                "Explain likely file-changing steps without running a command.",
            ),
            command_line("gate", None, "Block until a manual approval is decided."),
            command_line(
                "log",
                None,
                "Show the audit log of secret pulls and command runs.",
            ),
            command_line("audit", None, "Verify and inspect the audit log."),
            HelpLine::plain(""),
            section_line("LOCAL SYSTEM"),
            command_line("open", None, "Open Automic Vault.app."),
            command_line("serve", None, "Start the local Nucleus protocol daemon."),
        ]
    }

    fn legend_lines(&self) -> Vec<HelpLine<'static>> {
        vec![
            legend_rule("┌", "┐"),
            HelpLine::fragments(vec![
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed("│  "),
                },
                HelpFragment {
                    style: HelpStyle::Red,
                    text: Cow::Borrowed("LEGEND"),
                },
                HelpFragment {
                    style: HelpStyle::Dim,
                    text: Cow::Borrowed("                      │"),
                },
            ]),
            legend_blank(),
            legend_syntax("<>", "required"),
            legend_syntax("[]", "optional"),
            legend_syntax("...", "repeatable"),
            legend_mark(Self::SECTION_MARKER, "system domain"),
            legend_syntax("i, ls, up", "aliases"),
            legend_blank(),
            legend_rule("└", "┘"),
        ]
    }

    fn print_with_legend(&self, line: &HelpLine<'_>, legend: Option<&HelpLine<'_>>) {
        let left = line.render(self.color);
        if let Some(legend) = legend
            && line.width() < Self::LEGEND_COLUMN
        {
            let gap = Self::LEGEND_COLUMN - line.width();
            println!("{left}{}{}", " ".repeat(gap), legend.render(self.color));
            return;
        }
        println!("{left}");
    }

    fn rule(&self) -> String {
        paint(&"─".repeat(self.rule_width()), HelpStyle::Red, self.color)
    }

    fn top_rule(&self) -> String {
        let width = self.rule_width();
        if width < 2 {
            return paint("★", HelpStyle::Red, self.color);
        }
        format!(
            "{}{}",
            paint(&"─".repeat(width - 2), HelpStyle::Red, self.color),
            paint(" ★", HelpStyle::Red, self.color)
        )
    }

    fn rule_with_star(&self) -> String {
        let width = self.rule_width();
        if width < 7 {
            return self.rule();
        }

        let left = width / 2 - 2;
        let right = width - left - 4;
        format!(
            "{} {}  {}", // 2 spaces on right because the star renders wide
            paint(&"─".repeat(left), HelpStyle::Red, self.color),
            paint("★", HelpStyle::Red, self.color),
            paint(&"─".repeat(right), HelpStyle::Red, self.color)
        )
    }

    fn rule_width(&self) -> usize {
        self.columns.clamp(48, 120)
    }

    fn usage_line(&self) -> String {
        HelpLine::fragments(vec![
            HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed("  "),
            },
            HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed(self.program),
            },
            HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed(" "),
            },
            HelpFragment {
                style: HelpStyle::Dim,
                text: Cow::Borrowed("<"),
            },
            HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed("subcommand"),
            },
            HelpFragment {
                style: HelpStyle::Dim,
                text: Cow::Borrowed(">"),
            },
            HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed(" "),
            },
            HelpFragment {
                style: HelpStyle::Dim,
                text: Cow::Borrowed("["),
            },
            HelpFragment {
                style: HelpStyle::Primary,
                text: Cow::Borrowed("args"),
            },
            HelpFragment {
                style: HelpStyle::Dim,
                text: Cow::Borrowed("..."),
            },
            HelpFragment {
                style: HelpStyle::Dim,
                text: Cow::Borrowed("]"),
            },
        ])
        .render(self.color)
    }
}

fn section_line(title: &'static str) -> HelpLine<'static> {
    let prefix_width = 2 + title.chars().count() + 1;
    let rule_width = HelpScreen::COMMAND_PANE_WIDTH.saturating_sub(prefix_width);
    HelpLine::fragments(vec![
        HelpFragment {
            style: HelpStyle::Red,
            text: Cow::Borrowed(HelpScreen::SECTION_MARKER),
        },
        HelpFragment {
            style: HelpStyle::Red,
            text: Cow::Borrowed(" "),
        },
        HelpFragment {
            style: HelpStyle::Red,
            text: Cow::Borrowed(title),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Borrowed(" "),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Owned("─".repeat(rule_width)),
        },
    ])
}

fn command_line(
    command: &'static str,
    alias: Option<&'static str>,
    description: &'static str,
) -> HelpLine<'static> {
    let alias_width = alias.map_or(0, |value| value.chars().count() + 3);
    let mut fragments = vec![
        HelpFragment {
            style: HelpStyle::Primary,
            text: Cow::Borrowed("  "),
        },
        HelpFragment {
            style: HelpStyle::Primary,
            text: Cow::Borrowed(command),
        },
    ];

    if let Some(alias) = alias {
        fragments.push(HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Owned(format!(" ({alias})")),
        });
    }

    fragments.extend([
        HelpFragment {
            style: HelpStyle::Primary,
            text: Cow::Owned(command_padding(command, alias_width)),
        },
        HelpFragment {
            style: HelpStyle::Primary,
            text: Cow::Borrowed(description),
        },
    ]);
    HelpLine::fragments(fragments)
}

fn command_padding(command: &str, alias_width: usize) -> String {
    " ".repeat(
        HelpScreen::DESC_COLUMN
            .saturating_sub(2)
            .saturating_sub(command.chars().count() + alias_width),
    )
}

fn terminal_columns() -> usize {
    if let Ok(columns) = env::var("COLUMNS")
        && let Ok(columns) = columns.parse::<usize>()
        && columns > 0
    {
        return columns;
    }

    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) };
    if rc == 0 && size.ws_col > 0 {
        usize::from(size.ws_col)
    } else {
        120
    }
}

fn stdout_supports_ansi() -> bool {
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }

    if env::var("CLICOLOR_FORCE").is_ok_and(|value| value != "0") {
        return true;
    }

    std::io::stdout().is_terminal() && env::var("TERM").map_or(true, |term| term != "dumb")
}

fn paint(text: &str, style: HelpStyle, color: bool) -> String {
    if !color {
        return text.to_string();
    }

    let code = match style {
        HelpStyle::Primary => return text.to_string(),
        HelpStyle::Red => "38;2;224;90;71",
        HelpStyle::Dim => "2",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn legend_rule(left: &'static str, right: &'static str) -> HelpLine<'static> {
    HelpLine::fragments(vec![
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Borrowed(left),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Owned("─".repeat(30)),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Borrowed(right),
        },
    ])
}

fn legend_blank() -> HelpLine<'static> {
    HelpLine::fragments(vec![HelpFragment {
        style: HelpStyle::Dim,
        text: Cow::Borrowed("│                              │"),
    }])
}

fn legend_syntax(token: &'static str, description: &'static str) -> HelpLine<'static> {
    legend_item(token, description, HelpStyle::Dim)
}

fn legend_mark(token: &'static str, description: &'static str) -> HelpLine<'static> {
    legend_item(token, description, HelpStyle::Red)
}

fn legend_item(
    token: &'static str,
    description: &'static str,
    token_style: HelpStyle,
) -> HelpLine<'static> {
    HelpLine::fragments(vec![
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Borrowed("│  "),
        },
        HelpFragment {
            style: token_style,
            text: Cow::Borrowed(token),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Owned(" ".repeat(10_usize.saturating_sub(token.chars().count()))),
        },
        HelpFragment {
            style: HelpStyle::Primary,
            text: Cow::Borrowed(description),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Owned(" ".repeat(18_usize.saturating_sub(description.chars().count()))),
        },
        HelpFragment {
            style: HelpStyle::Dim,
            text: Cow::Borrowed("│"),
        },
    ])
}

pub(crate) fn print_mode_usage(mode: Mode, program: &str) {
    match mode {
        Mode::I => print_i_usage(program),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn set(values: &[(&'static str, Option<&str>)]) -> Self {
            let saved = values
                .iter()
                .map(|(key, _)| (*key, env::var_os(key)))
                .collect::<Vec<_>>();
            for (key, value) in values {
                match value {
                    Some(value) => unsafe { env::set_var(key, value) },
                    None => unsafe { env::remove_var(key) },
                }
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..).rev() {
                match value {
                    Some(value) => unsafe { env::set_var(key, value) },
                    None => unsafe { env::remove_var(key) },
                }
            }
        }
    }

    #[test]
    fn help_screen_layout_covers_rules_legend_and_color_paths() {
        let compact = HelpScreen::new("av", 1, false);
        assert_eq!(compact.rule_width(), 48);
        assert!(compact.top_rule().ends_with("★"));
        assert!(compact.rule_with_star().contains("★"));

        let wide = HelpScreen::new("av", 160, true);
        assert_eq!(wide.rule_width(), 120);
        assert!(wide.top_rule().contains("\x1b[38;2;224;90;71m"));
        assert!(wide.rule_with_star().contains("★"));
        assert!(wide.usage_line().contains("subcommand"));

        let commands = wide.command_lines();
        assert!(
            commands
                .iter()
                .any(|line| line.render(false).contains("install (i)"))
        );
        assert!(
            commands
                .iter()
                .any(|line| line.render(false).contains("LOCAL SYSTEM"))
        );

        let legend = wide.legend_lines();
        assert_eq!(legend.len(), 10);
        assert!(legend[3].render(false).contains("required"));
        assert!(legend[6].render(true).contains("\x1b[38;2;224;90;71m"));

        wide.print_with_legend(&commands[0], legend.first());
        compact.print_with_legend(&commands[0], legend.first());
        HelpScreen::new("vault", 120, false).print();
    }

    #[test]
    fn terminal_environment_helpers_cover_columns_and_color_flags() {
        let _lock = crate::global_test_env_lock().lock().unwrap();

        {
            let _env = EnvGuard::set(&[
                ("COLUMNS", Some("96")),
                ("NO_COLOR", None),
                ("CLICOLOR_FORCE", Some("1")),
                ("TERM", Some("dumb")),
            ]);
            assert_eq!(terminal_columns(), 96);
            assert!(stdout_supports_ansi());
        }

        {
            let _env = EnvGuard::set(&[
                ("COLUMNS", Some("0")),
                ("NO_COLOR", Some("1")),
                ("CLICOLOR_FORCE", Some("1")),
            ]);
            assert!(terminal_columns() > 0);
            assert!(!stdout_supports_ansi());
        }

        {
            let _env = EnvGuard::set(&[
                ("COLUMNS", None),
                ("NO_COLOR", None),
                ("CLICOLOR_FORCE", Some("0")),
                ("TERM", Some("dumb")),
            ]);
            assert!(terminal_columns() > 0);
            assert!(!stdout_supports_ansi());
        }
    }
}
