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
    match sts.assume_role(&AssumeRoleRequest{
            role_arn: "bogus".to_owned(),
            role_session_name: "rusoto_test_session".to_owned(),
            ..Default::default()
        }) {
        Err(AssumeRoleError::Unknown(msg)) =>
            assert!(msg.contains("validation error detected: Value 'bogus' at 'roleArn' failed to satisfy constraint")),
        err =>
            panic!("this should have been an Unknown STSError: {:?}", err)
    }

    match sts.get_session_token(
        &GetSessionTokenRequest {
            token_code: Some("bogus".to_owned()),
            ..Default::default()
        }) {
        Err(GetSessionTokenError::Unknown(msg)) =>
        panic!("blah: {:#?}", msg), 
            //assert!(msg.contains("Invalid TokenCode bogus")),
        err => 
            panic!("this should have been an Unknown STSError: {:?}", err)
    }
}
