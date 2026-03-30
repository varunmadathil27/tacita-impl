use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tacita::local::{
    load_config, partial_decrypt_bundle, register_committee_member, write_json,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Register {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        committee_member_id: u64,
        #[arg(long)]
        out: PathBuf,
    },
    PartialDecrypt {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aggregate_material: PathBuf,
        #[arg(long)]
        aggregate_bundle: PathBuf,
        #[arg(long)]
        committee_member_id: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Register {
            config,
            committee_member_id,
            out,
        } => {
            let config = load_config(&config)?;
            let registration = register_committee_member(&config, committee_member_id)?;
            write_json(&out, &registration)?;
        }
        Command::PartialDecrypt {
            config,
            aggregate_material,
            aggregate_bundle,
            committee_member_id,
            out,
        } => {
            let config = load_config(&config)?;
            let partial = partial_decrypt_bundle(
                &config,
                &aggregate_material,
                &aggregate_bundle,
                committee_member_id,
            )?;
            write_json(&out, &partial)?;
        }
    }
    Ok(())
}
