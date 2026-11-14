//! Explicit scheduling for owned reconnect fixtures, never a library default.
use verysync_sidecar::{Client, NetworkPatch};
pub async fn configure(client: &Client) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let previous = client
        .network_configuration()
        .await?
        .reconnection_interval_seconds;
    let actual = client
        .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
        .await?;
    assert!(actual.requested_fields_match);
    assert_eq!(actual.configuration.reconnection_interval_seconds, 5);
    println!("owned reconnect fixture redial seconds: previous={previous} explicit=5");
    Ok(())
}
