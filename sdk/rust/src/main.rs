mod client;
mod config;
mod credential;
mod error;
mod history;
mod model;
mod parser;
mod proof;
mod scan;
mod target;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "codex-security")]
#[command(about = "Rust SDK for Codex Security - fundamental architecture rewrite")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        target: String,

        #[arg(long)]
        model: Option<String>,

        #[arg(long, default_value = "medium")]
        effort: String,

        #[arg(long)]
        output: Option<PathBuf>,
    },
    Login {
        #[arg(long)]
        auth_method: Option<String>,
    },
    Logout,
    Proof {
        #[arg(long)]
        receipt: Option<String>,
    },
    Status,
    Config {
        #[arg(long)]
        set: Option<String>,

        #[arg(long)]
        get: Option<String>,
    },
    History {
        #[arg(long)]
        clear: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let command = cli.command;
    let config = load_config()?;

    match command {
        Commands::Scan {
            target,
            model,
            effort,
            output,
        } => {
            info!("Starting scan of {}", target);
            let result = scan::execute_scan(&config, &target, model.as_deref(), &effort).await?;

            if let Some(path) = output {
                let json = serde_json::to_string_pretty(&result)?;
                std::fs::write(&path, json)?;
                info!("Scan result written to {}", path.display());
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            info!(
                "Scan complete: {} findings with status {:?}",
                result.findings.len(),
                result.status
            );
        }
        Commands::Login { auth_method } => {
            let method = auth_method.as_deref().unwrap_or(
                if std::env::var("CODEX_AUTH_METHOD").unwrap_or_default() == "chatgpt" {
                    "chatgpt"
                } else {
                    "api-key"
                },
            );
            credential::ensure_credential(method)?;
            info!("Login successful using {}", method);
        }
        Commands::Logout => {
            let path = credential::credential_path()?;
            if path.exists() {
                std::fs::remove_file(&path)?;
                info!("Credentials removed from {}", path.display());
            } else {
                info!("No credentials found");
            }
        }
        Commands::Proof { receipt } => {
            let trace = proof::load_or_generate_receipt(receipt.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&trace)?);
        }
        Commands::Status => {
            info!("codex-security-sdk v0.1.0");
            info!("SDK backend: Rust");
            info!("Architecture: four-space hexagonal");
            info!("API endpoint: {}", mask_api_key(&config.api_endpoint));
            if let Ok(Some(cred)) = credential::load_credential() {
                info!("Authenticated: {} ({})", cred.auth_method, cred.created_at);
            } else {
                info!("Not authenticated");
            }
        }
        Commands::Config { set, get } => match (set, get) {
            (Some(set_value), None) => {
                info!("Config option 'set' not yet implemented");
            }
            (None, Some(get_value)) => match get_value.as_str() {
                "api_endpoint" => println!("{}", config.api_endpoint),
                "auth_method" => println!("{:?}", config.auth_method),
                _ => anyhow::bail!("Unknown config key: {}", get_value),
            },
            _ => anyhow::bail!("Specify either --set or --get"),
        },
        Commands::History { clear } => {
            if clear {
                let path = history::history_path()?;
                if path.exists() {
                    std::fs::remove_file(&path)?;
                    info!("Scan history cleared");
                } else {
                    info!("No scan history found");
                }
            } else {
                match history::ScanHistory::load() {
                    Ok(history) => {
                        if history.is_empty() {
                            info!("No scan history found");
                        } else {
                            for record in history.records.iter().rev().take(20) {
                                println!(
                                    "{} - {} ({} findings) - {}",
                                    record.completed_at,
                                    record.target.display_name(),
                                    record.findings_count,
                                    record.result_status
                                );
                            }
                        }
                    }
                    Err(_) => {
                        info!("No scan history found");
                    }
                }
            }
        }
    }

    Ok(())
}

fn load_config() -> anyhow::Result<config::SdkConfig> {
    config::SdkConfig::from_env()
}

fn mask_api_key(endpoint: &str) -> String {
    if let Some(pos) = endpoint.find("://") {
        let scheme = &endpoint[..pos + 3];
        if let Some(rest) = endpoint.get(pos + 3..) {
            if let Some(at) = rest.find('@') {
                let masked = "*".repeat(at);
                return format!("{}{}", scheme, rest.replace(&rest[..at], &masked));
            }
        }
    }
    endpoint.to_string()
}
