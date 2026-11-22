//! Read connection and synthetic payload evidence from two explicit test nodes.

#[path = "acceptance_pair/observe.rs"]
mod observe;

use std::path::PathBuf;

#[tokio::main]
async fn main() -> observe::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let plan = PathBuf::from(
        args.next()
            .ok_or("usage: observe_acceptance_pair ABSOLUTE_PLAN.json")?,
    );
    if args.next().is_some() {
        return Err("Supply one absolute path to the private test plan.".into());
    }
    println!("{}", serde_json::to_string(&observe::run(&plan).await?)?);
    eprintln!("Finished checking the two test nodes. The report describes the observed connection and file results.");
    Ok(())
}
