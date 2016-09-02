//! Types for loading and managing AWS access credentials for API requests.

use std::fmt;
use std::env::*;
use std::env;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Error as IoError;
use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::sync::Mutex;
use std::cell::RefCell;
use std::str::FromStr;
use hyper::Client;
use hyper::header::Connection;
use regex::Regex;
use chrono::{Duration, UTC, DateTime, ParseError};
use serde_json::{Value, from_str};
use std::time::Duration as StdDuration;
use ini::Ini;
use ini::ini;
use region;

/// AWS API access credentials, including access key, secret key, token (for IAM profiles), and
/// expiration timestamp.
#[derive(Clone, Debug)]
pub struct AwsCredentials {
    key: String,
    secret: String,
    token: Option<String>,
    expires_at: DateTime<UTC>
}

impl AwsCredentials {
    /// Create a new `AwsCredentials` from a key ID, secret key, optional access token, and expiry
    /// time.
    pub fn new<K, S>(key:K, secret:S, token:Option<String>, expires_at:DateTime<UTC>)
    -> AwsCredentials where K:Into<String>, S:Into<String> {
        AwsCredentials {
            key: key.into(),
            secret: secret.into(),
            token: token,
            expires_at: expires_at,
        }
    }

    /// Get a reference to the access key ID.
    pub fn aws_access_key_id(&self) -> &str {
        &self.key
    }

    /// Get a reference to the secret access key.
    pub fn aws_secret_access_key(&self) -> &str {
        &self.secret
    }

    /// Get a reference to the expiry time.
    pub fn expires_at(&self) -> &DateTime<UTC> {
        &self.expires_at
    }

    /// Get a reference to the access token.
    pub fn token(&self) -> &Option<String> {
        &self.token
    }

    /// Determine whether or not the credentials are expired.
    fn credentials_are_expired(&self) -> bool {
        // This is a rough hack to hopefully avoid someone requesting creds then sitting on them
        // before issuing the request:
        self.expires_at < UTC::now() + Duration::seconds(20)
    }
}

#[derive(Debug, PartialEq)]
pub struct CredentialsError{
    pub message: String
}

impl CredentialsError {
    fn new(message: &str) -> CredentialsError {
        CredentialsError {
            message: message.to_string()
        }
    }
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for CredentialsError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl From<ParseError> for CredentialsError {
    fn from(err: ParseError) -> CredentialsError {
        CredentialsError::new(err.description())
    }
}

impl From<IoError> for CredentialsError {
    fn from(err: IoError) -> CredentialsError {
        CredentialsError::new(err.description())
    }
}

impl From<ini::Error> for CredentialsError {
    fn from(err: ini::Error) -> CredentialsError {
        CredentialsError::new(err.description())
    }
}

impl From<region::ParseRegionError> for CredentialsError {
    fn from(err: region::ParseRegionError) -> CredentialsError {
        CredentialsError::new(err.description())
    }
}

/// A trait for types that produce `AwsCredentials`.
pub trait ProvideAwsCredentials {
    /// Produce a new `AwsCredentials`.
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError>;
}

/// Provides AWS credentials from environment variables.
pub struct EnvironmentProvider;

impl ProvideAwsCredentials for EnvironmentProvider {
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
		credentials_from_environment()
    }
}

fn credentials_from_environment() -> Result<AwsCredentials, CredentialsError> {
    let env_key = match var("AWS_ACCESS_KEY_ID") {
        Ok(val) => val,
        Err(_) => return Err(CredentialsError::new("No AWS_ACCESS_KEY_ID in environment"))
    };
    let env_secret = match var("AWS_SECRET_ACCESS_KEY") {
        Ok(val) => val,
        Err(_) => return Err(CredentialsError::new("No AWS_SECRET_ACCESS_KEY in environment"))
    };

    if env_key.is_empty() || env_secret.is_empty() {
        return Err(CredentialsError::new("Couldn't find either AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY or both in environment."));
    }

    // Present when using temporary credentials, e.g. on Lambda with IAM roles
    let token = match var("AWS_SESSION_TOKEN") {
        Ok(val) => {
            if val.is_empty() {
                None
            } else {
                Some(val)
            }
        }
        Err(_) => None,
    };

    Ok(AwsCredentials::new(env_key, env_secret, token, in_ten_minutes()))

}

/// Provides AWS credentials from a profile in a credentials file.
#[derive(Clone, Debug)]
pub struct ProfileProvider {
    credentials: Option<AwsCredentials>,
    file_path: PathBuf,
    config_file_path: PathBuf,
    profile: String,
}

impl ProfileProvider {
    /// Create a new `ProfileProvider` for the default credentials file path and profile name.
    pub fn new() -> Result<ProfileProvider, CredentialsError> {
        // Default credentials file location:
        // ~/.aws/credentials (Linux/Mac)
        // %USERPROFILE%\.aws\credentials  (Windows)
        let dot_aws_location = match env::home_dir() {
            Some(home_path) => home_path.join(PathBuf::from(".aws")),
            None => return Err(CredentialsError::new("The environment variable HOME must be set.")),
        };

        let mut profile_location = dot_aws_location.clone();
        profile_location.push("credentials");

        let mut config_location = dot_aws_location.clone();
        config_location.push("config");

        Ok(ProfileProvider {
            credentials: None,
            file_path: profile_location,
            config_file_path: config_location,
            profile: "default".to_owned(),
        })
    }

    /// Create a new `ProfileProvider` for the credentials file at the given path, using
    /// the given profile.
    pub fn with_configuration<F, C, P>(file_path: F, config_file_path: C, profile: P) -> ProfileProvider
    where F: Into<PathBuf>, C: Into<PathBuf>, P: Into<String> {
        ProfileProvider {
            credentials: None,
            file_path: file_path.into(),
            config_file_path: config_file_path.into(),
            profile: profile.into(),
        }
    }

    /// Get a reference to the credentials file path.
    pub fn file_path(&self) -> &Path {
        self.file_path.as_ref()
    }

    /// Get a reference to the config file path.
    pub fn config_file_path(&self) -> &Path {
        self.config_file_path.as_ref()
    }

    /// Get a reference to the profile name.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Set the credentials file path.
    pub fn set_file_path<F>(&mut self, file_path: F) where F: Into<PathBuf> {
        self.file_path = file_path.into();
    }

    /// Set the credentials file path.
    pub fn set_config_file_path<F>(&mut self, config_file_path: F) where F: Into<PathBuf> {
        self.config_file_path = config_file_path.into();
    }

    /// Set the profile name.
    pub fn set_profile<P>(&mut self, profile: P) where P: Into<String> {
        self.profile = profile.into();
    }
}

impl ProvideAwsCredentials for ProfileProvider {
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        let config = try!(parse_config_file(self.config_file_path()));

        let mut profile_name: Option<&str> = config.profiles.get(self.profile()).and_then(|p| {
            p.source_profile.as_ref().map(|s| &s[..])
        });

        profile_name = profile_name.or_else(|| Some(self.profile()));

    	parse_credentials_file(self.file_path()).and_then(|mut profiles| {
            profiles.remove(profile_name.unwrap()).ok_or(CredentialsError::new("profile not found"))
    	})
   }
}

fn parse_credentials_file(file_path: &Path) -> Result<HashMap<String, AwsCredentials>, CredentialsError> {
    match fs::metadata(file_path) {
        Err(_) => return Err(CredentialsError::new("Couldn't stat credentials file.")),
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(CredentialsError::new("Couldn't open file."));
            }
        }
    };

    let file = try!(File::open(file_path));

    let profile_regex = Regex::new(r"^\[([^\]]+)\]$").unwrap();
    let mut profiles: HashMap<String, AwsCredentials> = HashMap::new();
    let mut access_key: Option<String> = None;
    let mut secret_key: Option<String> = None;
    let mut profile_name: Option<String> = None;

    let file_lines = BufReader::new(&file);
    for line in file_lines.lines() {

        let unwrapped_line : String = line.unwrap();

        // skip comments
        if unwrapped_line.starts_with('#') {
            continue;
        }

        // handle the opening of named profile blocks
        if profile_regex.is_match(&unwrapped_line) {

            if profile_name.is_some() && access_key.is_some() && secret_key.is_some() {
                let creds = AwsCredentials::new(access_key.unwrap(), secret_key.unwrap(), None, in_ten_minutes());
                profiles.insert(profile_name.unwrap(), creds);
            }

            access_key = None;
            secret_key = None;

            let caps = profile_regex.captures(&unwrapped_line).unwrap();
            profile_name = Some(caps.at(1).unwrap().to_string());
            continue;
        }

        // otherwise look for key=value pairs we care about
        let lower_case_line = unwrapped_line.to_ascii_lowercase().to_string();

        if lower_case_line.contains("aws_access_key_id") &&
            access_key.is_none()
        {
            let v: Vec<&str> = unwrapped_line.split('=').collect();
            if !v.is_empty() {
                access_key = Some(v[1].trim_matches(' ').to_string());
            }
        } else if lower_case_line.contains("aws_secret_access_key") &&
            secret_key.is_none()
        {
            let v: Vec<&str> = unwrapped_line.split('=').collect();
            if !v.is_empty() {
                secret_key = Some(v[1].trim_matches(' ').to_string());
            }
        }

        // we could potentially explode here to indicate that the file is invalid

    }

    if profile_name.is_some() && access_key.is_some() && secret_key.is_some() {
        let creds = AwsCredentials::new(access_key.unwrap(), secret_key.unwrap(), None, in_ten_minutes());
        profiles.insert(profile_name.unwrap(), creds);
    }

    if profiles.is_empty() {
        return Err(CredentialsError::new("No credentials found."));
    }

    Ok(profiles)
}

pub trait LoadFromPath where Self: Sized {
    type Error: Sized + 'static;

    fn load_from_path(filename: &Path) -> Result<Self, Self::Error>;
}

impl LoadFromPath for Ini {
    type Error = ini::Error;

    fn load_from_path(filename: &Path) -> Result<Ini, Self::Error> {
        let mut reader = match File::open(filename) {
            Err(e) => {
                return Err(ini::Error {
                    line: 0,
                    col: 0,
                    msg: format!("Unable to open `{:?}`: {}", filename, e),
                })
            }
            Ok(r) => r,
        };
        Ini::read_from(&mut reader)
    }
}

pub struct ConfigProfile {
    pub role_arn: Option<String>,
    pub source_profile: Option<String>,
    pub region: Option<region::Region>,
}

pub struct Config {
    pub default_region: Option<region::Region>,
    pub profiles: HashMap<String, ConfigProfile>,
}

fn get_profile_name_from_section_name(section_name: &str) -> Option<String> {
    let prefix = "profile ";
    if section_name.starts_with(prefix) {
        Some(section_name.chars().skip(prefix.len()).collect())
    } else {
        None
    }
}

fn parse_config_file(file_path: &Path) -> Result<Config, CredentialsError> {
    let ini = try!(Ini::load_from_path(file_path));

    let default_section = ini.section(Some("default".to_owned()));
    let maybe_default_region_name = default_section.and_then(|s| s.get("region"));
    let default_region = if let Some(default_region_name) = maybe_default_region_name {
        Some(try!(region::Region::from_str(default_region_name)))
    } else {
        None
    };

    let mut profiles = HashMap::new();

    for key in ini.sections() {
        if let Some(section_name) = key.as_ref() {  
            let section = ini.section(key.to_owned()).unwrap();

            if let Some(profile_name) = get_profile_name_from_section_name(section_name) {
                let maybe_region_name = section.get("region");
                let region = if let Some(region_name) = maybe_region_name {
                    Some(try!(region::Region::from_str(region_name)))
                } else {
                    None
                };
                let source_profile = section.get("source_profile").map(|s| s.to_owned());
                let role_arn = section.get("role_arn").map(|s| s.to_owned());

                profiles.insert(profile_name, ConfigProfile {
                    role_arn: role_arn,
                    source_profile: source_profile,
                    region: region,
                });
            }
        }
    }

    Ok(Config {
        default_region: default_region,
        profiles: profiles,
    })
}

#[cfg(feature = "sts")]
mod sts {
    use super::{AwsCredentials, CredentialsError, ProvideAwsCredentials};
    use ::sts::StsClient;
    use ::Region;
    use std::path::{Path, PathBuf};

    /// Provides AWS credentials from Secure Token Service
    #[derive(Clone, Debug)]
    pub struct StsProvider<P> where P: ProvideAwsCredentials + Clone {
        base_provider: P,
        config_file_path: Option<PathBuf>,
        region: Option<Region>,
        role_arn: Option<String>,
        profile: Option<String>,
    }

    impl <P> StsProvider<P> where P: ProvideAwsCredentials + Clone {
        pub fn new(base_provider: P) -> StsProvider<P> {
            StsProvider {
                base_provider: base_provider,
                region: None,
                role_arn: None,
                profile: None,
                config_file_path: None,
            }
        }

        pub fn get_region(&self) -> Option<Region> {
            self.region
        }

        pub fn set_region(&mut self, region: Option<Region>) {
            self.region = region;
        }

        pub fn get_role_arn(&self) -> Option<&str> {
            self.role_arn.as_ref().map(|s| &s[..])
        }

        pub fn set_role_arn(&mut self, role_arn: Option<String>) {
            self.role_arn = role_arn;
        }

        pub fn get_profile(&self) -> Option<&str> {
            self.profile.as_ref().map(|s| &s[..])
        }

        /// Set the profile name.
        pub fn set_profile(&mut self, profile: Option<String>) {
            self.profile = profile;
        }

        pub fn get_config_file_path(&self) -> Option<&Path> {
            self.config_file_path.as_ref().map(|p| p.as_ref())
        }

        /// Set the credentials file path.
        pub fn set_config_file_path(&mut self, config_file_path: Option<PathBuf>) {
            self.config_file_path = config_file_path.into();
        }
    }

    impl <P> ProvideAwsCredentials for StsProvider<P> where P: ProvideAwsCredentials + Clone {
        fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
            // read ~/.aws/config
            let file_path = try!(self.config_file_path.as_ref().ok_or(CredentialsError::new("No StsProvider config_file_path set.")));
            let config = try!(super::parse_config_file(&file_path));

            // get default region
            let default_region = config.default_region;
            // get profile
            let profile_name = try!(self.profile.as_ref().ok_or(CredentialsError::new("No StsProvider profile set.")));
            let profile = try!(config.profiles.get(profile_name).ok_or(CredentialsError::new("StsProvider profile not found in config")));
            // get region override from profile?
            let region = self.region.or_else(|| profile.region).or_else(|| default_region).unwrap_or(Region::UsEast1);
            // get source_profile from profile
            let source_profile = profile.source_profile;
            // get role_arn
            let role_arn = profile.role_arn;
            // set source_profile on base_provider
            // create client
            // assume role
            // get session token 
            let region = unimplemented!();

            let client = StsClient::new(self.base_provider.clone(), region);

            unimplemented!()
        }
    }
}

#[cfg(feature = "sts")]
pub use self::sts::*;

/// Provides AWS credentials from a resource's IAM role.
pub struct IamProvider;

impl ProvideAwsCredentials for IamProvider {
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
	
		// TODO: backoff and retry on failure.
        let mut address : String = "http://169.254.169.254/latest/meta-data/iam/security-credentials".to_string();
        let mut client = Client::new();
        client.set_read_timeout(Some(StdDuration::from_secs(15)));
        let mut response;
        match client.get(&address)
            .header(Connection::close()).send() {
                Err(_) => return Err(CredentialsError::new("Couldn't connect to metadata service")), // add Why?
                Ok(received_response) => response = received_response
            };

        let mut body = String::new();
        if let Err(_) = response.read_to_string(&mut body) {
			return Err(CredentialsError::new("Didn't get a parsable response body from metadata service"));
        }

        address.push_str("/");
        address.push_str(&body);
        body = String::new();
        match client.get(&address)
            .header(Connection::close()).send() {
                Err(_) => return Err(CredentialsError::new("Didn't get a parseable response body from instance role details")),
                Ok(received_response) => response = received_response
            };

        if let Err(_) = response.read_to_string(&mut body) {
            return Err(CredentialsError::new("Had issues with reading iam role response: {}"));
        }

        let json_object: Value;
        match from_str(&body) {
            Err(_) => return Err(CredentialsError::new("Couldn't parse metadata response body.")),
            Ok(val) => json_object = val
        };

        let access_key;
        match json_object.find("AccessKeyId") {
            None => return Err(CredentialsError::new("Couldn't find AccessKeyId in response.")),
            Some(val) => access_key = val.as_str().expect("AccessKeyId value was not a string").to_owned().replace("\"", "")
        };

        let secret_key;
        match json_object.find("SecretAccessKey") {
            None => return Err(CredentialsError::new("Couldn't find SecretAccessKey in response.")),
            Some(val) => secret_key = val.as_str().expect("SecretAccessKey value was not a string").to_owned().replace("\"", "")
        };

        let expiration;
        match json_object.find("Expiration") {
            None => return Err(CredentialsError::new("Couldn't find Expiration in response.")),
            Some(val) => expiration = val.as_str().expect("Expiration value was not a string").to_owned().replace("\"", "")
        };

        let expiration_time = try!(expiration.parse());

        let token_from_response;
        match json_object.find("Token") {
            None => return Err(CredentialsError::new("Couldn't find Token in response.")),
            Some(val) => token_from_response = val.as_str().expect("Token value was not a string").to_owned().replace("\"", "")
        };

        Ok(AwsCredentials::new(access_key, secret_key, Some(token_from_response), expiration_time))

    }
}

/// Wrapper for `ProvideAwsCredentials` that caches the credentials returned by the
/// wrapped provider.  Each time the credentials are accessed, they are checked to see if
/// they have expired, in which case they are retrieved from the wrapped provider again.
pub struct BaseAutoRefreshingProvider<P, T> {
	credentials_provider: P,
	cached_credentials: T
}

/// Threadsafe `AutoRefreshingProvider` that locks cached credentials with a `Mutex`
pub type AutoRefreshingProviderSync<P> = BaseAutoRefreshingProvider<P, Mutex<AwsCredentials>>;

impl <P: ProvideAwsCredentials> AutoRefreshingProviderSync<P> {
    pub fn with_mutex(provider: P) -> Result<AutoRefreshingProviderSync<P>, CredentialsError> {
		let creds = try!(provider.credentials());
		Ok(BaseAutoRefreshingProvider { 
			credentials_provider: provider, 
			cached_credentials: Mutex::new(creds) 
		})
	}
}

impl <P: ProvideAwsCredentials> ProvideAwsCredentials for BaseAutoRefreshingProvider<P, Mutex<AwsCredentials>> {
	fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
		let mut creds = self.cached_credentials.lock().unwrap();
		if creds.credentials_are_expired() {			
			*creds = try!(self.credentials_provider.credentials());
		}
		Ok(creds.clone())
	}
}

/// `!Sync` `AutoRefreshingProvider` that caches credentials in a `RefCell`
pub type AutoRefreshingProvider<P> = BaseAutoRefreshingProvider<P, RefCell<AwsCredentials>>;

impl <P: ProvideAwsCredentials> AutoRefreshingProvider<P> {
	pub fn with_refcell(provider: P) -> Result<AutoRefreshingProvider<P>, CredentialsError> {
		let creds = try!(provider.credentials());
		Ok(BaseAutoRefreshingProvider { 
			credentials_provider: provider, 
			cached_credentials: RefCell::new(creds) 
		})
	}
}

impl <P: ProvideAwsCredentials> ProvideAwsCredentials for BaseAutoRefreshingProvider<P, RefCell<AwsCredentials>> {
	fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {

		let mut creds = self.cached_credentials.borrow_mut();
		
		if creds.credentials_are_expired() {
			*creds = try!(self.credentials_provider.credentials());
		}	

		Ok(creds.clone())
	}
}


/// The credentials provider you probably want to use if you don't require Sync for your AWS services.
/// Wraps a `ChainProvider` in an `AutoRefreshingProvider` that uses a `RefCell` to cache credentials
///
/// The underlying `ChainProvider` checks multiple sources for credentials, and the `AutoRefreshingProvider`
/// refreshes the credentials automatically when they expire.  The `RefCell` allows this caching to happen
/// without the overhead of a `Mutex`, but is `!Sync`.
///
/// For a `Sync` implementation of the same, see `DefaultCredentialsProviderSync`
pub type DefaultCredentialsProvider = AutoRefreshingProvider<ChainProvider>;

impl DefaultCredentialsProvider {
    pub fn new() -> Result<DefaultCredentialsProvider, CredentialsError> {
        Ok(try!(AutoRefreshingProvider::with_refcell(ChainProvider::new())))
    }
}

/// The credentials provider you probably want to use if you do require your AWS services.
/// Wraps a `ChainProvider` in an `AutoRefreshingProvider` that uses a `Mutex` to lock credentials in a
/// threadsafe manner.
///
/// The underlying `ChainProvider` checks multiple sources for credentials, and the `AutoRefreshingProvider`
/// refreshes the credentials automatically when they expire.  The `Mutex` allows this caching to happen
/// in a Sync manner, incurring the overhead of a Mutex when credentials expire and need to be refreshed.
///
/// For a `!Sync` implementation of the same, see `DefaultCredentialsProvider`
pub type DefaultCredentialsProviderSync = AutoRefreshingProviderSync<ChainProvider>;

impl DefaultCredentialsProviderSync {
    pub fn new() -> Result<DefaultCredentialsProviderSync, CredentialsError> {
        Ok(try!(AutoRefreshingProviderSync::with_mutex(ChainProvider::new())))
    }
}

/// Provides AWS credentials from multiple possible sources using a priority order.
///
/// The following sources are checked in order for credentials when calling `credentials`:
///
/// 1. Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
/// 2. AWS credentials file. Usually located at `~/.aws/credentials`.
/// 3. IAM instance profile. Will only work if running on an EC2 instance with an instance profile/role.
///
/// If the sources are exhausted without finding credentials, an error is returned.
#[derive(Debug, Clone)]
pub struct ChainProvider {
    profile_provider: Option<ProfileProvider>,
}

impl ProvideAwsCredentials for ChainProvider {
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {

	EnvironmentProvider.credentials()
		.or_else(|_| {
            match self.profile_provider {
                Some(ref provider) => provider.credentials(),
                None => Err(CredentialsError::new(""))
            }
        })
		.or_else(|_| IamProvider.credentials())
		.or_else(|_| Err(CredentialsError::new("Couldn't find AWS credentials in environment, credentials file, or IAM role.")))
    }
}

impl ChainProvider {
    /// Create a new `ChainProvider` using a `ProfileProvider` with the default settings.
    pub fn new() -> ChainProvider {
        ChainProvider {
            profile_provider: ProfileProvider::new().ok(),
        }
    }

    /// Create a new `ChainProvider` using the provided `ProfileProvider`.
    pub fn with_profile_provider(profile_provider: ProfileProvider)
    -> ChainProvider {
        ChainProvider {
            profile_provider: Some(profile_provider),
        }
    }
}

fn in_ten_minutes() -> DateTime<UTC> {
    UTC::now() + Duration::seconds(600)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn parse_credentials_file_default_profile() {
        let result = super::parse_credentials_file(
            Path::new("tests/sample-data/default_profile_credentials")
        );
        assert!(result.is_ok());

        let profiles = result.ok().unwrap();
        assert_eq!(profiles.len(), 1);

        let default_profile = profiles.get("default").unwrap();
        assert_eq!(default_profile.aws_access_key_id(), "foo");
        assert_eq!(default_profile.aws_secret_access_key(), "bar");
    }

    #[test]
    fn parse_credentials_file_multiple_profiles() {
        let result = super::parse_credentials_file(
            Path::new("tests/sample-data/multiple_profile_credentials")
        );
        assert!(result.is_ok());

        let profiles = result.ok().unwrap();
        assert_eq!(profiles.len(), 2);

        let foo_profile = profiles.get("foo").unwrap();
        assert_eq!(foo_profile.aws_access_key_id(), "foo_access_key");
        assert_eq!(foo_profile.aws_secret_access_key(), "foo_secret_key");

        let bar_profile = profiles.get("bar").unwrap();
        assert_eq!(bar_profile.aws_access_key_id(), "bar_access_key");
        assert_eq!(bar_profile.aws_secret_access_key(), "bar_secret_key");

    }

    #[test]
    fn profile_provider_happy_path() {
        let provider = ProfileProvider::with_configuration(
            "tests/sample-data/multiple_profile_credentials",
            "foo",
        );
        let result = provider.credentials();

        assert!(result.is_ok());

        let creds = result.ok().unwrap();
        assert_eq!(creds.aws_access_key_id(), "foo_access_key");
        assert_eq!(creds.aws_secret_access_key(), "foo_secret_key");
     }

    #[test]
    fn profile_provider_bad_profile() {
        let provider = ProfileProvider::with_configuration(
            "tests/sample-data/multiple_profile_credentials",
            "not_a_profile",
        );
        let result = provider.credentials();

        assert!(result.is_err());
        assert_eq!(result.err(), Some(CredentialsError::new("profile not found")));
    }

    #[test]
    fn profile_provider_profile_name() {
       let mut provider = ProfileProvider::new().unwrap();
       assert_eq!("default", provider.profile());
       provider.set_profile("foo");
       assert_eq!("foo", provider.profile());
    }

    #[test]
    fn credential_chain_explicit_profile_provider() {
        let profile_provider = ProfileProvider::with_configuration(
            "tests/sample-data/multiple_profile_credentials",
            "foo",
        );

        let chain = ChainProvider::with_profile_provider(profile_provider);

        let credentials = chain.credentials().expect(
            "Failed to get credentials from default provider chain with manual profile",
        );

        assert_eq!(credentials.aws_access_key_id(), "foo_access_key");
        assert_eq!(credentials.aws_secret_access_key(), "foo_secret_key");
    }

    #[test]
    fn existing_file_no_credentials() {
        let result = super::parse_credentials_file(Path::new("tests/sample-data/no_credentials"));
        assert_eq!(result.err(), Some(CredentialsError::new("No credentials found.")))
    }

    #[test]
    fn parse_credentials_bad_path() {
        let result = super::parse_credentials_file(Path::new("/bad/file/path"));
        assert_eq!(result.err(), Some(CredentialsError::new("Couldn't stat credentials file.")));
    }

    #[test]
    fn parse_credentials_directory_path() {
        let result = super::parse_credentials_file(Path::new("tests/"));
        assert_eq!(result.err(), Some(CredentialsError::new("Couldn't open file.")));
    }
}

