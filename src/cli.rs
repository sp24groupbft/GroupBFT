use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "GBFT")]
#[command(about = "Group BFT", version)]
pub(crate) struct Cli {
    /// Path to the config file
    #[arg(short, long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Set ID of current node.
    #[arg(short, long, default_value_t = 0)]
    pub(crate) id: u64,

    /// Addresses of known nodes.
    #[arg(short, long, default_value_t = String::from("localhost:8123"))]
    addr: String,

    /// Use HotStuff consensus.
    /// Hotstuff is temporarily unavailable in the current version.
  
    //#[arg(short, long)]
    //pub(crate) disable_gbft: bool,

    /// Dynamic Group BFT is not particularly encapsulated. 
    /// If you want to switch to Dynamic Group BFT, 
    /// the simplest way is to rearrange the voterset 
    /// during the view-change phase
    
    //#[arg(short, long)]
    //pub(crate) enable_dgbft: bool,

    /// Set injection_rate, default value is 100_000 (tx/s).
    #[arg(short, long)]
    pub(crate) rate: Option<u64>,

    /// Set transaction_size, default value is 256 (Bytes).
    #[arg(short, long)]
    pub(crate) transaction_size: Option<usize>,

    /// Set batch_size, default value is 100 (tx/block).
    #[arg(short, long)]
    pub(crate) batch_size: Option<usize>,

    /// Pretend to be a failure nodes.
    #[arg(long)]
    pub(crate) pretend_failure: bool,

    /// Disable metrics.
    #[arg(long)]
    pub(crate) disable_metrics: bool,

    /// Rotate leadership every `rotate_every` key blocks.
    #[arg(long)]
    pub(crate) leader_rotation: Option<usize>,

    /// Maximum number of transactions in the mempool.
    #[arg(long)]
    pub(crate) mempool_size: Option<usize>,

    /// Pacemaker timeout.
    #[arg(long)]
    pub(crate) timeout: Option<usize>,

    /// Export metrics to file when node exits.
    #[arg(short, long)]
    pub(crate) export_path: Option<PathBuf>,

    /// Subcommands
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Parser, Debug)]
pub(crate) enum Commands {
    /// Run the node within memory network.
    MemoryTest {
        /// Number of nodes.
        #[arg(short, long, default_value_t = 4)]
        number: usize,
        #[arg(short, long, default_value_t = 1)]
        per_number: usize,
    },

    /// Run the node in memory network with some nodes are failure.
    FailTest {
        /// Number of failures.
        #[arg(short, long, default_value_t = 1)]
        number: usize,
        #[arg(short, long, default_value_t = 1)]
        per_number: usize,
    },

    /// Generate all configs for a single test.
    ///
    /// This command distributes `number` replicas into `hosts`,
    /// automatically assign id and addr.
    ConfigGen {
        /// Number of nodes.
        #[arg(short, long, default_value_t = 4)]
        number: usize,
        /// Number of nodes per group.
        #[arg(short, long, default_value_t = 1)]
        per_number: usize,

        /// hosts to distribute replicas.
        hosts: Vec<String>,

        /// Path to export configs.
        #[arg(short, long, value_name = "DIR")]
        export_dir: Option<PathBuf>,

        /// automatically export configs to a new directory.
        #[arg(short, long)]
        auto_naming: bool,

        /// Write all the configs and scripts to file.
        #[arg(short, long)]
        write_file: bool,

        /// Pretend to be failure nodes
        #[arg(short, long, default_value_t = 0)]
        failure_nodes: usize,
    },
}
