//! Admin Panel Exposure Detection Module
//! Identifies exposed administrative consoles (phpMyAdmin, Webmin, cPanel) via path heuristics.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum number of admin paths to probe (bounded)
const MAX_ADMIN_PATHS: usize = 200;

/// Common administrative panel paths with service identification
const ADMIN_PANELS: &[(&str, &str)] = &[
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/phpMyAdmin/", "phpMyAdmin"),
    ("/pma/", "phpMyAdmin"),
    ("/mysql/", "MySQL Admin"),
    ("/myadmin/", "MySQL Admin"),
    ("/webmin/", "Webmin"),
    ("/cpanel/", "cPanel"),
    ("/whm/", "WHM"),
    ("/plesk/", "Plesk"),
    ("/adminer.php", "Adminer"),
    ("/administrator/", "Generic Admin"),
    ("/admin/", "Generic Admin"),
    ("/manage/", "Management Console"),
    ("/manager/", "Manager Console"),
    ("/control/", "Control Panel"),
    ("/dashboard/", "Dashboard"),
    ("/console/", "Console"),
    ("/wp-admin/", "WordPress Admin"),
    ("/joomla/administrator/", "Joomla Admin"),
    ("/drupal/admin/", "Drupal Admin"),
    ("/jenkins/", "Jenkins"),
    ("/hudson/", "Hudson"),
    ("/solr/", "Apache Solr"),
    ("/elasticsearch/", "Elasticsearch"),
    ("/kibana/", "Kibana"),
    ("/grafana/", "Grafana"),
    ("/prometheus/", "Prometheus"),
    ("/nagios/", "Nagios"),
    ("/zabbix/", "Zabbix"),
    ("/cockpit/", "Cockpit"),
    ("/portainer/", "Portainer"),
    ("/rancher/", "Rancher"),
    ("/openshift/", "OpenShift"),
    ("/vcenter/", "VMware vCenter"),
    ("/ovirt/", "oVirt"),
    ("/proxmox/", "Proxmox"),
    ("/freepbx/", "FreePBX"),
    ("/asterisk/", "Asterisk"),
];

/// Admin panel scanner struct
pub struct AdminPanelScanner {
    client: HttpClient,
}

impl AdminPanelScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Scan for exposed admin panels
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        let mut found_panels = Vec::new();
        
        // Probe bounded set of admin paths
        for (path, service) in ADMIN_PANELS.iter().take(MAX_ADMIN_PATHS) {
            let url = format!("{}{}", base, path);
            
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                
                // Detect accessible panels (200, 401, 403 all indicate existence)
                if status == 200 || status == 401 || status == 403 {
                    let mut confidence = 70;
                    
                    // Increase confidence based on response characteristics
                    if let Ok(body) = response.text().await {
                        let body_lower = body.to_lowercase();
                        
                        // Check for service-specific signatures
                        if body_lower.contains(&service.to_lowercase()) 
                            || body_lower.contains("login")
                            || body_lower.contains("password")
                            || body_lower.contains("authenticate") {
                            confidence = 90;
                        }
                        
                        // Check for known admin panel titles
                        if body_lower.contains(&format!("{} login", service.to_lowercase())) {
                            confidence = 95;
                        }
                    }
                    
                    // Check headers for service identification
                    if let Some(server) = response.headers().get("Server") {
                        if server.contains(service) {
                            confidence = 95;
                        }
                    }
                    
                    if let Some(x_powered) = response.headers().get("X-Powered-By") {
                        if x_powered.contains(service) {
                            confidence = 95;
                        }
                    }
                    
                    found_panels.push((*path).to_string());
                    
                    evidences.push(Evidence::ExposedAdminPanel {
                        service: service.to_string(),
                        url: url.clone(),
                        path: (*path).to_string(),
                        status_code: status.as_u16(),
                        confidence,
                        remediation: self.get_remediation(service),
                    });
                }
            }
        }
        
        // Add summary evidence if multiple panels found
        if found_panels.len() > 1 {
            evidences.push(Evidence::MultipleAdminPanels {
                count: found_panels.len(),
                panels: found_panels,
                base_url: base_url.to_string(),
                confidence: 85,
                remediation: "Restrict access to all administrative interfaces using network segmentation and authentication.".to_string(),
            });
        }
        
        evidences
    }

    /// Get service-specific remediation guidance
    fn get_remediation(&self, service: &str) -> String {
        match service {
            "phpMyAdmin" => "Restrict phpMyAdmin access by IP, use strong authentication, and keep updated.".to_string(),
            "Webmin" => "Configure Webmin to listen only on localhost or restrict by IP whitelist.".to_string(),
            "cPanel" | "WHM" => "Ensure cPanel/WHM is not publicly accessible. Use firewall rules to restrict access.".to_string(),
            "Plesk" => "Restrict Plesk access using firewall and enable two-factor authentication.".to_string(),
            "Jenkins" | "Hudson" => "Configure Jenkins security realm and authorization strategies. Disable CLI if not needed.".to_string(),
            "Grafana" | "Prometheus" | "Kibana" => "Enable authentication for monitoring dashboards. Do not expose to public internet.".to_string(),
            "Portainer" | "Rancher" | "OpenShift" => "Secure container management interfaces with RBAC and network policies.".to_string(),
            "vCenter" | "Proxmox" | "oVirt" => "Virtualization management must be isolated. Use dedicated management network.".to_string(),
            _ => "Restrict access using authentication, IP whitelisting, and network segmentation.".to_string(),
        }
    }

    /// Quick check if any admin panel exists
    pub async fn has_admin_panel(&self, base_url: &str) -> bool {
        let base = base_url.trim_end_matches('/');
        
        // Quick check most common paths first
        let quick_paths = ["/admin/", "/administrator/", "/phpmyadmin/", "/webmin/"];
        
        for path in quick_paths.iter() {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                if status == 200 || status == 401 || status == 403 {
                    return true;
                }
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = AdminPanelScanner::new(client);
    }

    #[test]
    fn test_bounded_paths() {
        assert!(ADMIN_PANELS.len() <= MAX_ADMIN_PATHS);
    }
}
