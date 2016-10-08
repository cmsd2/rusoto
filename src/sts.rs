//! The AWS STS API.

#![allow(unused_imports)]

include!(concat!(env!("OUT_DIR"), "/sts.rs"));

pub use self::credential::*;

mod credential {
    use ::ini;
    use ::credential::{AwsCredentials, ProfileProvider, ConfigProfile, CredentialsError,
        ProvideAwsCredentials, Config, CredentialsParser};
    use super::{AssumeRoleRequest, GetSessionTokenRequest, StsClient};
    use ::Region;
    use std::path::{Path, PathBuf};
    use hyper::Client;
    use chrono::*;

    pub trait NewAwsCredsForStsCreds {
        fn new_for_credentials(sts_creds: ::sts::Credentials) -> Result<AwsCredentials, CredentialsError>;
    }

    impl NewAwsCredsForStsCreds for AwsCredentials {
        fn new_for_credentials(sts_creds: ::sts::Credentials) -> Result<AwsCredentials, CredentialsError> {
            let expires_at = try!(sts_creds.expiration.parse::<DateTime<UTC>>().map_err(|e|
                CredentialsError::new(format!("error parsing credentials expiry: {}", e))));

            Ok(AwsCredentials::new(
                sts_creds.access_key_id, 
                sts_creds.secret_access_key, 
                Some(sts_creds.session_token), 
                expires_at))
        }
    }

    /// Provides AWS credentials from Secure Token Service
    pub struct StsProvider<P> where P: ProvideAwsCredentials + Clone {
        base_provider: P,
        credentials_file_path: Option<PathBuf>,
        config_file_path: Option<PathBuf>,
        region: Option<Region>,
        role_arn: Option<String>,
        profile: Option<String>,
        session_name: Option<String>,
    }

    // impl <P> Clone for StsProvider<P> where P: ProvideAwsCredentials + Clone {
    //     fn clone(&self) -> StsProvider<P> {
    //         StsProvider {
    //             base_provider: self.base_provider.clone(),
    //             config_file_path: self.config_file_path.clone(),
    //             region: self.region.clone(),
    //             role_arn: self.role_arn.clone(),
    //             profile: self.profile.clone(),
    //         }
    //     }
    // }

    impl <P> StsProvider<P> where P: ProvideAwsCredentials + Clone {
        pub fn new(base_provider: P) -> Result<StsProvider<P>, CredentialsError> {
            let config_file_path = try!(ProfileProvider::default_config_path());
            let credentials_file_path = try!(ProfileProvider::default_credentials_path());

            Ok(StsProvider {
                base_provider: base_provider,
                region: None,
                role_arn: None,
                profile: None,
                credentials_file_path: Some(credentials_file_path),
                config_file_path: Some(config_file_path),
                session_name: None,
            })
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

        pub fn get_credentials_file_path(&self) -> Option<&Path> {
            self.credentials_file_path.as_ref().map(|p| p.as_ref())
        }

        /// Set the credentials file path.
        pub fn set_credentials_file_path(&mut self, credentials_file_path: Option<PathBuf>) {
            self.credentials_file_path = credentials_file_path.into();
        }

        pub fn get_config_file_path(&self) -> Option<&Path> {
            self.config_file_path.as_ref().map(|p| p.as_ref())
        }

        /// Set the config file path.
        pub fn set_config_file_path(&mut self, config_file_path: Option<PathBuf>) {
            self.config_file_path = config_file_path.into();
        }
        
        pub fn get_session_name(&self) -> Option<&str> {
            self.session_name.as_ref().map(|s| &s[..])
        }

        pub fn set_session_name(&mut self, session_name: Option<String>) {
            self.session_name = session_name;
        }

        pub fn default_session_name() -> &'static str {
            "rusoto"
        }

        pub fn assume_role<R,S>(client: &StsClient<P,Client>, role_arn: R, session_name: S) -> Result<AwsCredentials, CredentialsError> 
                where R: Into<String>, S: Into<String> {
            match client.assume_role(&AssumeRoleRequest{
                role_arn: role_arn.into(),
                role_session_name: session_name.into(),
                ..Default::default()
            }) {
                Err(err) =>
                    Err(CredentialsError::new(format!("Sts AssumeRoleError: {:?}", err))),
                Ok(resp) => {
                    let creds = try!(resp.credentials.ok_or(CredentialsError::new("no credentials in response")));
                    
                    AwsCredentials::new_for_credentials(creds)
                }
            }
        }

        pub fn get_session_token<S>(client: &StsClient<P,Client>, code: Option<S>) -> Result<AwsCredentials, CredentialsError> 
                where S: Into<String> {
            match client.get_session_token(
                &GetSessionTokenRequest {
                    token_code: code.map(|s| s.into()),
                    ..Default::default()
                }) {
                Ok(resp) => {
                    let creds = try!(resp.credentials.ok_or(CredentialsError::new("no credentials in response")));

                    AwsCredentials::new_for_credentials(creds)
                },
                err => 
                    Err(CredentialsError::new(format!("StsProvider get_session_token error: {:?}", err)))
            }
        }
    }

    impl <P> ProvideAwsCredentials for StsProvider<P> where P: ProvideAwsCredentials + Clone {
        fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
            // read ~/.aws/config
            let file_path = try!(self.config_file_path.as_ref().ok_or(CredentialsError::new("No StsProvider config_file_path set.")));
            let mut config = try!(Config::parse_config_file(&file_path));
            let credentials_file_path = try!(self.credentials_file_path.as_ref().ok_or(CredentialsError::new("No StsProvider credentials_file_path set.")));
            let basic_profiles = try!(CredentialsParser::parse_credentials_file(&credentials_file_path));
            let default_region = config.default_region;

            for (k, _creds) in basic_profiles {
                config.profiles.entry(k.clone()).or_insert(ConfigProfile::new(k));
            }

            // get named profile if any or default profile if present
            let profile: Option<&::credential::ConfigProfile>;
            if let Some(ref profile_name) = self.profile {
                profile = Some(try!(config.profiles.get(profile_name)
                    .ok_or(CredentialsError::new("StsProvider profile not found in config"))));
            } else {
                profile = config.profiles.get("default");
            }

            debug!("StsProvider using profile {:?}", profile.map(|p| &p.name));

            // get region from profile unless overridden
            let region = self.region
                .or_else(|| profile.and_then(|p| p.region))
                .or_else(|| default_region)
                .unwrap_or(Region::UsEast1);

            debug!("StsProvider using region {:?}", region);
            
            // get role_arn from profile
            let maybe_role_arn = profile.and_then(|p| p.role_arn.as_ref());

            debug!("StsProvider using role_arn {:?}", maybe_role_arn);
            
            let client = StsClient::new(self.base_provider.clone(), region);

            let session_name = self.get_session_name().unwrap_or(Self::default_session_name());

            debug!("StsProvider using session_name {:?}", session_name);

            if let Some(role_arn) = maybe_role_arn {
                Self::assume_role(&client, &role_arn[..], session_name)
            } else {
                let maybe_code: Option<&str> = None;
                Self::get_session_token(&client, maybe_code)
            }
        }
    }
}