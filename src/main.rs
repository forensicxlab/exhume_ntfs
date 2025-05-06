use clap::{Arg, ArgAction, Command, value_parser};
use clap_num::maybe_hex;
use exhume_body::{Body, BodySlice};
use exhume_ntfs::NTFS;
use log::{debug, error};
use serde_json::{Value, json};

fn main() {
    let matches = Command::new("exhume_ntfs")
        .version("0.1.O")
        .author("ForensicXlab")
        .about("Exhume the metadata from an ntfs filesystem.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("The format of the file, either 'raw' or 'ewf'."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The NTFS partition starts at address (decimal or hex)."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The size of the NTFS partition in sectors (decimal or hex)."),
        )
        .arg(
            Arg::new("pbs")
                .long("pbs")
                .action(ArgAction::SetTrue)
                .help("Display the partition boot sector information."),
        )
        .arg(
            Arg::new("file_id")
                .long("file")
                .value_parser(maybe_hex::<usize>)
                .help("Display the metadata about a specific file identifier."),
        )
        .arg(
            Arg::new("dir_entry")
                .short('d')
                .long("dir_entry")
                .requires("file_id")
                .action(ArgAction::SetTrue)
                .help("If --file is specified and it is a directory, list its directory entries."),
        )
        .arg(
            Arg::new("mft")
                .long("mft")
                .action(ArgAction::SetTrue)
                .help("Display the high level master file table information."),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .action(ArgAction::SetTrue)
                .requires("file_id")
                .help("Dump the file content to file_<ID>.bin (requires --file)"),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output certain structures (pbs, file, mft) in JSON format."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level"),
        )
        .get_matches();

    // Initialize logger.
    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    let file_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let offset = matches.get_one::<u64>("offset").unwrap();
    let size = matches.get_one::<u64>("size").unwrap();
    let show_pbs = matches.get_flag("pbs");
    let dump_file = matches.get_flag("dump");
    let json_output = matches.get_flag("json");
    let file_id = matches.get_one::<usize>("file_id").copied().unwrap_or(0);
    let show_dir_entry = matches.get_flag("dir_entry");

    // 1) Prepare the "body" and create an ExtFS instance.
    let mut body = Body::new(file_path.to_owned(), format);
    debug!("Created Body from '{}'", file_path);

    let partition_size = *size * body.get_sector_size() as u64;
    let mut slice = match BodySlice::new(&mut body, *offset, partition_size) {
        Ok(sl) => sl,
        Err(e) => {
            error!("Could not create BodySlice: {}", e);
            return;
        }
    };

    let mut filesystem = match NTFS::new(&mut slice) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Couldn't open NTFS: {}", e);
            return;
        }
    };

    if show_pbs {
        if json_output {
            match serde_json::to_string_pretty(&filesystem.pbs.to_json()) {
                Ok(s) => println!("{}", s),
                Err(e) => error!("Error serializing PBS to JSON: {}", e),
            }
        } else {
            println!("{}", filesystem.pbs.to_string());
        }
    }

    if file_id > 0 {
        let file = filesystem.get_file_id(file_id as u64).unwrap();

        if show_dir_entry {
            let entries = filesystem
                .list_dir(file_id as u64)
                .expect("Could not list directory entries for this record.");

            if json_output {
                let arr: Vec<Value> = entries.iter().map(|de| de.to_json()).collect();
                let dir_json = json!({ "dir_entries": arr });
                println!("{}", serde_json::to_string_pretty(&dir_json).unwrap());
            } else {
                for file in entries {
                    println!("{}  {}", file.file_id, file.name);
                }
            }
        } else if dump_file {
            match filesystem.read_file(&file) {
                Ok(data) => {
                    let out_name = format!("file_{:X}.bin", file_id);
                    if let Err(e) = std::fs::write(&out_name, &data) {
                        error!("Cannot write dump: {}", e);
                    } else {
                        println!("Dumped {} bytes to {}", data.len(), out_name);
                    }
                }
                Err(e) => error!("Dump failed: {}", e),
            }
        } else {
            if json_output {
                println!("{}", file.to_json())
            } else {
                println!("{}", file.to_string());
            }
        }
    }
}
