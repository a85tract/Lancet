use std::error::Error;
use std::path::PathBuf;

use a85_qlancet::trace::TraceFormat;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(());
    }
    let command = args.remove(0);
    match command.as_str() {
        "klancet" => run_klancet_cmd(&args),
        other => Err(format!("unknown command '{other}'").into()),
    }
}

fn run_klancet_cmd(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut positional = Vec::new();
    let mut format = TraceFormat::Auto;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--trace-format=") {
            format = value.parse()?;
        } else if arg == "--trace-format" {
            let Some(value) = iter.next() else {
                return Err("--trace-format requires auto|qlt|legacy".into());
            };
            format = value.parse()?;
        } else {
            positional.push(arg.clone());
        }
    }
    if positional.len() != 3 {
        print_usage();
        return Err("klancet requires <trace> <config> <out>".into());
    }
    let summary = a85_qlancet::run_klancet(
        PathBuf::from(&positional[0]),
        PathBuf::from(&positional[1]),
        PathBuf::from(&positional[2]),
        format,
    )?;
    println!("violations: {}", summary.ownership_violations);
    println!(
        "summary   : {}",
        PathBuf::from(&positional[2]).join("summary.json").display()
    );
    Ok(())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!(
        "  a85_qlancet klancet <trace> <config.json> <out_dir> [--trace-format auto|qlt|legacy]"
    );
}
