
pub struct PathParser;

impl PathParser {
    pub fn parse_debian_path(path: &str) -> Result<DebianPath, String> {
        if !path.starts_with("/debian/") {
            return Err("Invalid Debian path".to_string());
        }
        
        let remaining = &path[8..]; // Remove "/debian/"
        
        if remaining.starts_with("dists/") {
            Self::parse_release_path(remaining)
        } else if remaining.starts_with("pool/") {
            Self::parse_package_path(remaining)
        } else {
            Err("Unknown Debian path type".to_string())
        }
    }
    
    fn parse_release_path(path: &str) -> Result<DebianPath, String> {
        // Example: /debian/dists/bookworm/InRelease
        // Example: /debian/dists/bookworm/main/binary-amd64/Packages.gz
        let parts: Vec<&str> = path.split('/').collect();
        
        if parts.len() < 2 {
            return Err("Invalid release path format".to_string());
        }
        
        let suite = parts[1].to_string(); // bookworm, bullseye, etc.
        
        // Handle different path structures
        let (component, architecture, filename) = if parts.len() == 2 {
            // /debian/dists/bookworm/InRelease
            (None, None, None)
        } else if parts.len() == 3 {
            // /debian/dists/bookworm/Release
            (None, None, Some(parts[2].to_string()))
        } else if parts.len() == 4 {
            // /debian/dists/bookworm/main/InRelease
            (Some(parts[2].to_string()), None, Some(parts[3].to_string()))
        } else if parts.len() == 5 {
            // Check if it's a directory ending with / or a file
            if parts[4].ends_with('/') {
                // /debian/dists/bookworm/main/binary-amd64/
                (
                    Some(parts[2].to_string()),
                    Some(parts[3].trim_end_matches('/').to_string()),
                    None,
                )
            } else {
                // /debian/dists/bookworm/main/binary-amd64/Packages.gz
                (
                    Some(parts[2].to_string()),
                    Some(parts[3].to_string()),
                    Some(parts[4].to_string()),
                )
            }
        } else {
            // /debian/dists/bookworm/main/binary-amd64/Packages.gz
            (
                parts.get(2).map(|s| s.to_string()),
                parts.get(4).map(|s| s.to_string()),
                parts.last().map(|s| s.to_string()),
            )
        };
        
        Ok(DebianPath {
            path_type: PathType::Release,
            suite,
            component,
            architecture,
            filename,
        })
    }
    
    fn parse_package_path(path: &str) -> Result<DebianPath, String> {
        // Example: pool/main/a/apt/apt_2.6.1_amd64.deb (after removing /debian/)
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        if parts.len() < 4 {
            return Err("Invalid package path format".to_string());
        }
        
        // Pool path structure: pool/{component}/{first-letter}/{package}/{package}_{version}_{arch}.deb
        // parts[0]="pool", parts[1]="main", parts[2]="a", parts[3]="apt", ...
        let component = parts.get(1).map(|s| s.to_string());
        let filename = parts.last().map(|s| s.to_string());
        
        Ok(DebianPath {
            path_type: PathType::Package,
            suite: String::new(), // Packages don't have suite in path
            component,
            architecture: None, // Will be extracted from .deb filename if needed
            filename,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DebianPath {
    pub path_type: PathType,
    pub suite: String,
    pub component: Option<String>,
    pub architecture: Option<String>,
    pub filename: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PathType {
    Release,    // Release files, Packages indices
    Package,    // .deb files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_release_path_simple() {
        let path = "/debian/dists/bookworm/InRelease";
        let result = PathParser::parse_debian_path(path).unwrap();
        
        assert_eq!(result.path_type, PathType::Release);
        assert_eq!(result.suite, "bookworm");
        assert!(result.component.is_none());
    }

    #[test]
    fn test_parse_release_path_packages() {
        let path = "/debian/dists/bookworm/main/binary-amd64/Packages.gz";
        let result = PathParser::parse_debian_path(path).unwrap();
        
        assert_eq!(result.path_type, PathType::Release);
        assert_eq!(result.suite, "bookworm");
        assert_eq!(result.component.as_deref(), Some("main"));
        assert_eq!(result.architecture.as_deref(), Some("binary-amd64"));
        assert_eq!(result.filename.as_deref(), Some("Packages.gz"));
    }

    #[test]
    fn test_parse_package_path() {
        let path = "/debian/pool/main/a/apt/apt_2.6.1_amd64.deb";
        let result = PathParser::parse_debian_path(path).unwrap();
        
        assert_eq!(result.path_type, PathType::Package);
        assert_eq!(result.component.as_deref(), Some("main"));
        assert_eq!(result.filename.as_deref(), Some("apt_2.6.1_amd64.deb"));
    }

    #[test]
    fn test_invalid_path() {
        assert!(PathParser::parse_debian_path("/ubuntu/dists/noble/Release").is_err());
        assert!(PathParser::parse_debian_path("/debian/invalid/path").is_err());
    }

    #[test]
    fn test_path_components_extraction() {
        let path = "/debian/dists/bullseye/main/source/Sources.gz";
        let result = PathParser::parse_debian_path(path).unwrap();
        
        assert_eq!(result.suite, "bullseye");
        assert_eq!(result.component.as_deref(), Some("main"));
        assert_eq!(result.architecture.as_deref(), Some("source"));
        assert_eq!(result.filename.as_deref(), Some("Sources.gz"));
    }
}
