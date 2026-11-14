//! Native LDAP settings, separate from actual GUI session authentication.
use super::Client;
use crate::{ConfigurationSectionUpdate, LdapConfiguration, LdapPatch, Result};
impl Client {
    /// Read actual native directory settings. This does not connect to LDAP.
    pub async fn ldap_configuration(&self) -> Result<LdapConfiguration> {
        self.connection
            .get_json("read native LDAP configuration", "rest/config/ldap")
            .await
    }
    /// PATCH only explicit directory fields, recheck identity and return actual
    /// readback. Does not change GUI auth mode, install certificates, perform a
    /// directory bind, retry a write or restart the native process.
    pub async fn update_ldap_configuration(
        &self,
        patch: &LdapPatch,
    ) -> Result<ConfigurationSectionUpdate<LdapConfiguration>> {
        patch.validate()?;
        self.patch_configuration_section("rest/config/ldap", patch)
            .await
    }
}
