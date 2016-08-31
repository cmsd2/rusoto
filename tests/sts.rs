#![cfg(feature = "sts")]

extern crate rusoto;

use rusoto::sts::StsClient;
use rusoto::sts::{AssumeRoleRequest, AssumeRoleError};
use rusoto::sts::{GetSessionTokenRequest, GetSessionTokenError};
use rusoto::{DefaultCredentialsProvider, Region};

#[test]
fn main() {
    let credentials = DefaultCredentialsProvider::new().unwrap();

    let sts = StsClient::new(credentials, Region::UsEast1);

    // http://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html
    match sts.assume_role(&AssumeRoleRequest::default()) {
        Ok(clusters) => {
            for arn in clusters.cluster_arns.unwrap_or(vec![]) {
                println!("arn -> {:?}", arn);
            }
        },
        Err(err) => {
            panic!("Error assuming role {:#?}", err);
        }
    }

    match sts.get_session_token(
        &GetSessionTokenRequest {
            token_code: Some("bogus".to_owned()),
            ..Default::default()
        }) {
        Err(GetSessionTokenError::InvalidParameter(msg)) => 
            assert!(msg.contains("Invalid TokenCode bogus")),
        _ => 
            panic!("this should have been an InvalidParameterException STSError")
    }
}
