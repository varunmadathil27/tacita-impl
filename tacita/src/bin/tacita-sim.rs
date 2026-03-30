use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tacita::local::{
    decode_stored_result, load_config, parse_round_inputs, run_simulation_round, write_json,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Round {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, help = "semicolon-separated plaintexts, e.g. 1,2;3,4;5,6")]
        inputs: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Round { config, inputs, out } => {
            let config = load_config(&config)?;
            let inputs = parse_round_inputs(&inputs)?;
            let round = run_simulation_round(&config, &inputs)?;
            let decoded = decode_stored_result(&round.result)?;
            write_json(&out, &round)?;
            println!(
                "round {} complete; aggregate plaintext = {:?}",
                config.round.round_id, decoded.slots
            );
        }
    }
    Ok(())
}
