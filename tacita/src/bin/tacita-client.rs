use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tacita::local::{
    load_config, parse_plaintext_spec, register_client, submit_client_input, write_json,
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
        client_id: u64,
        #[arg(long)]
        out: PathBuf,
    },
    Submit {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aggregate_material: PathBuf,
        #[arg(long)]
        client_id: u64,
        #[arg(long, help = "comma-separated slot values, e.g. 1,2")]
        plaintext: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Register {
            config,
            client_id,
            out,
        } => {
            let config = load_config(&config)?;
            let registration = register_client(&config, client_id)?;
            write_json(&out, &registration)?;
        }
        Command::Submit {
            config,
            aggregate_material,
            client_id,
            plaintext,
            out,
        } => {
            let config = load_config(&config)?;
            let plaintext = parse_plaintext_spec(&plaintext)?;
            let submission =
                submit_client_input(&config, &aggregate_material, client_id, &plaintext)?;
            write_json(&out, &submission)?;
        }
    }
    Ok(())
}
