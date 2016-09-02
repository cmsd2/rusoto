#![cfg(feature = "sts")]

extern crate rusoto;

use rusoto::sts::StsClient;
use rusoto::sts::{AssumeRoleRequest, AssumeRoleError};
use rusoto::sts::{GetSessionTokenRequest};
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
            token_code: Some("unused".to_owned()),
            ..Default::default()
        }) {
        Ok(tok) => {
            println!("{:?}", tok);
            assert!(tok.credentials.is_some()) },
        err => 
            panic!("this should have been a Session Token: {:?}", err)
    }
}
