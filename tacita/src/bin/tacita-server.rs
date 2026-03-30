use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tacita::local::{
    aggregate_submissions, derive_aggregate_material, finalize_aggregate_result, load_config,
    write_json,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    DeriveAggregateMaterial {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, required = true)]
        client_registration: Vec<PathBuf>,
        #[arg(long, required = true)]
        committee_registration: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    Aggregate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aggregate_material: PathBuf,
        #[arg(long, required = true)]
        submission: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    Finalize {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aggregate_material: PathBuf,
        #[arg(long)]
        aggregate_bundle: PathBuf,
        #[arg(long, required = true)]
        partial_decryption: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::DeriveAggregateMaterial {
            config,
            client_registration,
            committee_registration,
            out,
        } => {
            let config = load_config(&config)?;
            let material =
                derive_aggregate_material(&config, &client_registration, &committee_registration)?;
            write_json(&out, &material)?;
        }
        Command::Aggregate {
            config,
            aggregate_material,
            submission,
            out,
        } => {
            let config = load_config(&config)?;
            let bundle = aggregate_submissions(&config, &aggregate_material, &submission)?;
            write_json(&out, &bundle)?;
        }
        Command::Finalize {
            config,
            aggregate_material,
            aggregate_bundle,
            partial_decryption,
            out,
        } => {
            let config = load_config(&config)?;
            let result = finalize_aggregate_result(
                &config,
                &aggregate_material,
                &aggregate_bundle,
                &partial_decryption,
            )?;
            write_json(&out, &result)?;
        }
    }
    Ok(())
}
