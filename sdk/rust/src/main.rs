mod client;
mod config;
mod credential;
mod error;
mod model;
mod proof;
mod scan;

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
    Proof {
        #[arg(long)]
        receipt: Option<String>,
    },
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let command = cli.command;
    let config = load_config()?;

    match command {
        Commands::Scan { target, model, effort, output } => {
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
            let method = auth_method
                .as_deref()
                .unwrap_or(if std::env::var("CODEX_AUTH_METHOD").unwrap_or_default() == "chatgpt" {
                    "chatgpt"
                } else {
                    "api-key"
                });
            credential::ensure_credential(method)?;
            info!("Login successful using {}", method);
        }
        Commands::Proof { receipt } => {
            let trace = proof::load_or_generate_receipt(receipt.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&trace)?);
        }
        Commands::Status => {
            info!("codex-security-sdk v0.1.0");
            info!("SDK backend: Rust");
            info!("Architecture: four-space hexagonal");
        }
    }

    Ok(())
}

fn load_config() -> anyhow::Result<config::SdkConfig> {
    config::SdkConfig::from_env()
}