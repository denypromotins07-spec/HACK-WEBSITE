//! Error Signatures Database for SQL Injection Detection
//! Zero-copy signatures for PostgreSQL, MySQL, MSSQL, Oracle, and MariaDB errors.

use std::borrow::Cow;

/// Maximum number of signatures to retain (bounded memory)
const MAX_SIGNATURES: usize = 500;

/// Database error signature
#[derive(Debug, Clone)]
pub struct ErrorSignature<'a> {
    pub pattern: Cow<'a, str>,
    pub dbms: Cow<'a, str>,
    pub error_type: Cow<'a, str>,
    pub confidence: f64,
    pub case_sensitive: bool,
}

/// DBMS identification result from server header
#[derive(Debug, Clone)]
pub struct ServerSignature<'a> {
    pub dbms: Cow<'a, str>,
    pub version_pattern: Option<Cow<'a, str>>,
}

/// Zero-copy error signature database
pub struct ErrorSignatureDatabase {
    signatures: Vec<ErrorSignature<'static>>,
}

impl ErrorSignatureDatabase {
    /// Create a new signature database with pre-populated signatures
    pub fn new() -> Self {
        let mut db = Self {
            signatures: Vec::with_capacity(MAX_SIGNATURES),
        };
        db.populate_signatures();
        db
    }

    /// Populate with known database error signatures
    fn populate_signatures(&mut self) {
        // MySQL / MariaDB signatures
        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("You have an error in your SQL syntax"),
            dbms: Cow::Borrowed("MySQL"),
            error_type: Cow::Borrowed("syntax_error"),
            confidence: 0.95,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("check the manual that corresponds to your MySQL server version"),
            dbms: Cow::Borrowed("MySQL"),
            error_type: Cow::Borrowed("syntax_hint"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Warning: mysql_"),
            dbms: Cow::Borrowed("MySQL"),
            error_type: Cow::Borrowed("deprecated_function"),
            confidence: 0.85,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("mysqli_sql_exception"),
            dbms: Cow::Borrowed("MySQL"),
            error_type: Cow::Borrowed("exception"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Column count doesn't match value count"),
            dbms: Cow::Borrowed("MySQL"),
            error_type: Cow::Borrowed("value_mismatch"),
            confidence: 0.85,
            case_sensitive: false,
        });

        // PostgreSQL signatures
        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("ERROR:  syntax error at or near"),
            dbms: Cow::Borrowed("PostgreSQL"),
            error_type: Cow::Borrowed("syntax_error"),
            confidence: 0.95,
            case_sensitive: true,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("PG::SyntaxError:"),
            dbms: Cow::Borrowed("PostgreSQL"),
            error_type: Cow::Borrowed("pg_exception"),
            confidence: 0.95,
            case_sensitive: true,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("ERROR:  column"),
            dbms: Cow::Borrowed("PostgreSQL"),
            error_type: Cow::Borrowed("column_error"),
            confidence: 0.85,
            case_sensitive: true,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("does not exist"),
            dbms: Cow::Borrowed("PostgreSQL"),
            error_type: Cow::Borrowed("missing_object"),
            confidence: 0.7,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("invalid input syntax for type"),
            dbms: Cow::Borrowed("PostgreSQL"),
            error_type: Cow::Borrowed("type_conversion"),
            confidence: 0.9,
            case_sensitive: false,
        });

        // MSSQL signatures
        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Microsoft SQL Native Client"),
            dbms: Cow::Borrowed("MSSQL"),
            error_type: Cow::Borrowed("native_client"),
            confidence: 0.95,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("SQLServer ODBC Driver"),
            dbms: Cow::Borrowed("MSSQL"),
            error_type: Cow::Borrowed("odbc_driver"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Unclosed quotation mark after the character string"),
            dbms: Cow::Borrowed("MSSQL"),
            error_type: Cow::Borrowed("quote_error"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Incorrect syntax near"),
            dbms: Cow::Borrowed("MSSQL"),
            error_type: Cow::Borrowed("syntax_error"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("The conversion of the varchar value to data type int resulted in an out-of-range integer"),
            dbms: Cow::Borrowed("MSSQL"),
            error_type: Cow::Borrowed("conversion_error"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Msg "),
            dbms: Cow::Borrowed("MSSQL"),
            error_type: Cow::Borrowed("msg_prefix"),
            confidence: 0.75,
            case_sensitive: true,
        });

        // Oracle signatures
        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("ORA-"),
            dbms: Cow::Borrowed("Oracle"),
            error_type: Cow::Borrowed("ora_error"),
            confidence: 0.95,
            case_sensitive: true,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Oracle Database Driver"),
            dbms: Cow::Borrowed("Oracle"),
            error_type: Cow::Borrowed("driver_disclosure"),
            confidence: 0.9,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("PLS-"),
            dbms: Cow::Borrowed("Oracle"),
            error_type: Cow::Borrowed("plsql_error"),
            confidence: 0.9,
            case_sensitive: true,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("invalid identifier"),
            dbms: Cow::Borrowed("Oracle"),
            error_type: Cow::Borrowed("identifier_error"),
            confidence: 0.8,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("table or view does not exist"),
            dbms: Cow::Borrowed("Oracle"),
            error_type: Cow::Borrowed("missing_table"),
            confidence: 0.85,
            case_sensitive: false,
        });

        // Generic SQL error signatures
        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("SQL error"),
            dbms: Cow::Borrowed("Unknown"),
            error_type: Cow::Borrowed("generic_sql"),
            confidence: 0.5,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Database error"),
            dbms: Cow::Borrowed("Unknown"),
            error_type: Cow::Borrowed("generic_db"),
            confidence: 0.5,
            case_sensitive: false,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("JDBC"),
            dbms: Cow::Borrowed("Unknown"),
            error_type: Cow::Borrowed("jdbc_disclosure"),
            confidence: 0.6,
            case_sensitive: true,
        });

        self.add_signature(ErrorSignature {
            pattern: Cow::Borrowed("Hibernate"),
            dbms: Cow::Borrowed("Unknown"),
            error_type: Cow::Borrowed("orm_disclosure"),
            confidence: 0.6,
            case_sensitive: true,
        });
    }

    /// Add a signature to the database
    fn add_signature(&mut self, signature: ErrorSignature<'static>) {
        if self.signatures.len() < MAX_SIGNATURES {
            self.signatures.push(signature);
        }
    }

    /// Match error content against signatures (zero-copy)
    pub fn match_error<'a>(&self, content: &'a str) -> Option<&'a ErrorSignature<'a>> {
        for sig in &self.signatures {
            let matches = if sig.case_sensitive {
                content.contains(sig.pattern.as_ref())
            } else {
                content.to_lowercase().contains(&sig.pattern.to_lowercase())
            };

            if matches {
                return Some(sig);
            }
        }
        None
    }

    /// Identify DBMS from server header
    pub fn identify_dbms_from_server<'a>(&self, server_header: &'a str) -> Option<Cow<'a, str>> {
        let lower = server_header.to_lowercase();

        if lower.contains("mysql") {
            Some(Cow::Borrowed("MySQL"))
        } else if lower.contains("postgres") || lower.contains("postgresql") {
            Some(Cow::Borrowed("PostgreSQL"))
        } else if lower.contains("microsoft") || lower.contains("mssql") || lower.contains("sqlserver") {
            Some(Cow::Borrowed("MSSQL"))
        } else if lower.contains("oracle") {
            Some(Cow::Borrowed("Oracle"))
        } else if lower.contains("mariadb") {
            Some(Cow::Borrowed("MariaDB"))
        } else {
            None
        }
    }

    /// Get all signatures for a specific DBMS
    pub fn get_signatures_for_dbms(&self, dbms: &str) -> Vec<&ErrorSignature> {
        self.signatures
            .iter()
            .filter(|s| s.dbms.eq_ignore_ascii_case(dbms))
            .collect()
    }

    /// Get signature count
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

impl Default for ErrorSignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_signature_match() {
        let db = ErrorSignatureDatabase::new();
        let content = "You have an error in your SQL syntax; check the manual";
        
        let matched = db.match_error(content);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().dbms, "MySQL");
    }

    #[test]
    fn test_postgresql_signature_match() {
        let db = ErrorSignatureDatabase::new();
        let content = "ERROR:  syntax error at or near SELECT";
        
        let matched = db.match_error(content);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().dbms, "PostgreSQL");
    }

    #[test]
    fn test_mssql_signature_match() {
        let db = ErrorSignatureDatabase::new();
        let content = "Unclosed quotation mark after the character string 'admin'";
        
        let matched = db.match_error(content);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().dbms, "MSSQL");
    }

    #[test]
    fn test_oracle_signature_match() {
        let db = ErrorSignatureDatabase::new();
        let content = "ORA-00904: invalid identifier";
        
        let matched = db.match_error(content);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().dbms, "Oracle");
    }

    #[test]
    fn test_server_header_identification() {
        let db = ErrorSignatureDatabase::new();
        
        assert_eq!(db.identify_dbms_from_server("MySQL/5.7.32"), Some(Cow::Borrowed("MySQL")));
        assert_eq!(db.identify_dbms_from_server("Apache/2.4 + Phusion_Passenger"), None);
    }

    #[test]
    fn test_signature_count() {
        let db = ErrorSignatureDatabase::new();
        assert!(db.signature_count() > 10);
    }
}
