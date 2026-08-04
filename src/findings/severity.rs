//! Severity Classification for Findings
//! 
//! Defines Critical, High, Medium, Low, and Info severity levels
//! with scoring rules for vulnerability classification.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity levels for vulnerability findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    /// Informational - not a security issue
    Info = 0,
    /// Low risk - minimal impact
    Low = 1,
    /// Medium risk - moderate impact
    Medium = 2,
    /// High risk - significant impact
    High = 3,
    /// Critical risk - severe impact
    Critical = 4,
}

impl Severity {
    /// Get numeric CVSS-like score (0-100)
    pub fn score(self) -> u16 {
        match self {
            Severity::Info => 0,
            Severity::Low => 25,
            Severity::Medium => 50,
            Severity::High => 75,
            Severity::Critical => 100,
        }
    }
    
    /// Get human-readable label
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    
    /// Get color code for terminal output
    pub fn color_code(self) -> &'static str {
        match self {
            Severity::Info => "\x1b[90m",    // Gray
            Severity::Low => "\x1b[92m",     // Green
            Severity::Medium => "\x1b[93m",  // Yellow
            Severity::High => "\x1b[91m",    // Red
            Severity::Critical => "\x1b[95m", // Magenta
        }
    }
    
    /// Get CVSS range for this severity
    pub fn cvss_range(self) -> (f32, f32) {
        match self {
            Severity::Info => (0.0, 0.0),
            Severity::Low => (0.1, 3.9),
            Severity::Medium => (4.0, 6.9),
            Severity::High => (7.0, 8.9),
            Severity::Critical => (9.0, 10.0),
        }
    }
    
    /// Get recommended response time
    pub fn recommended_response_time(self) -> &'static str {
        match self {
            Severity::Info => "No action required",
            Severity::Low => "Next maintenance cycle",
            Severity::Medium => "Within 30 days",
            Severity::High => "Within 7 days",
            Severity::Critical => "Immediate action required",
        }
    }
    
    /// Determine if severity requires immediate attention
    pub fn requires_immediate_action(self) -> bool {
        matches!(self, Severity::Critical | Severity::High)
    }
    
    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "INFO" | "INFORMATIONAL" => Some(Severity::Info),
            "LOW" => Some(Severity::Low),
            "MEDIUM" | "MED" => Some(Severity::Medium),
            "HIGH" => Some(Severity::High),
            "CRITICAL" | "CRIT" => Some(Severity::Critical),
            _ => None,
        }
    }
    
    /// All severity levels in order
    pub fn all() -> Vec<Severity> {
        vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Scoring rules for calculating severity from multiple factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringRules {
    /// Base score weight
    pub base_weight: f32,
    /// Impact weight
    pub impact_weight: f32,
    /// Exploitability weight
    pub exploitability_weight: f32,
    /// Environmental factor weight
    pub environmental_weight: f32,
}

impl Default for ScoringRules {
    fn default() -> Self {
        Self {
            base_weight: 0.4,
            impact_weight: 0.3,
            exploitability_weight: 0.2,
            environmental_weight: 0.1,
        }
    }
}

impl ScoringRules {
    /// Calculate severity score from component scores
    pub fn calculate_score(
        &self,
        base_score: f32,
        impact_score: f32,
        exploitability_score: f32,
        environmental_score: f32,
    ) -> f32 {
        let total = base_score * self.base_weight
            + impact_score * self.impact_weight
            + exploitability_score * self.exploitability_weight
            + environmental_score * self.environmental_weight;
        
        total.min(100.0).max(0.0)
    }
    
    /// Determine severity from calculated score
    pub fn score_to_severity(score: f32) -> Severity {
        match score {
            s if s >= 90.0 => Severity::Critical,
            s if s >= 70.0 => Severity::High,
            s if s >= 40.0 => Severity::Medium,
            s if s >= 10.0 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

/// Builder for creating severity classifications
pub struct SeverityBuilder {
    base_score: f32,
    impact_factors: Vec<f32>,
    mitigating_factors: Vec<f32>,
}

impl SeverityBuilder {
    pub fn new(base_score: f32) -> Self {
        Self {
            base_score,
            impact_factors: Vec::new(),
            mitigating_factors: Vec::new(),
        }
    }
    
    pub fn with_impact(mut self, factor: f32) -> Self {
        self.impact_factors.push(factor.min(1.0).max(0.0));
        self
    }
    
    pub fn with_mitigation(mut self, factor: f32) -> Self {
        self.mitigating_factors.push(factor.min(1.0).max(0.0));
        self
    }
    
    pub fn build(self) -> Severity {
        let mut score = self.base_score;
        
        // Apply impact factors (increase severity)
        for factor in self.impact_factors {
            score += (100.0 - score) * factor * 0.3;
        }
        
        // Apply mitigating factors (decrease severity)
        for factor in self.mitigating_factors {
            score *= (1.0 - factor * 0.3);
        }
        
        ScoringRules::score_to_severity(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
    
    #[test]
    fn test_severity_scores() {
        assert_eq!(Severity::Info.score(), 0);
        assert_eq!(Severity::Low.score(), 25);
        assert_eq!(Severity::Medium.score(), 50);
        assert_eq!(Severity::High.score(), 75);
        assert_eq!(Severity::Critical.score(), 100);
    }
    
    #[test]
    fn test_severity_parsing() {
        assert_eq!(Severity::from_str("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_str("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str("med"), Some(Severity::Medium));
        assert_eq!(Severity::from_str("invalid"), None);
    }
    
    #[test]
    fn test_scoring_rules() {
        let rules = ScoringRules::default();
        let score = rules.calculate_score(80.0, 70.0, 60.0, 50.0);
        
        assert!(score > 0.0 && score <= 100.0);
        
        let severity = ScoringRules::score_to_severity(score);
        assert!(severity >= Severity::Medium);
    }
    
    #[test]
    fn test_severity_builder() {
        let severity = SeverityBuilder::new(50.0)
            .with_impact(0.8)
            .with_impact(0.5)
            .build();
        
        assert!(severity >= Severity::Medium);
    }
    
    #[test]
    fn test_immediate_action() {
        assert!(Severity::Critical.requires_immediate_action());
        assert!(Severity::High.requires_immediate_action());
        assert!(!Severity::Medium.requires_immediate_action());
        assert!(!Severity::Low.requires_immediate_action());
        assert!(!Severity::Info.requires_immediate_action());
    }
}
