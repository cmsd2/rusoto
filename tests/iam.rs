#![cfg(feature = "iam")]

extern crate rusoto;

use rusoto::iam::IamClient;
use rusoto::iam::{GetUserRequest, GetUserError};
use rusoto::{DefaultCredentialsProvider, Region};

#[test]
fn get_user() {
    let credentials = DefaultCredentialsProvider::new().unwrap();

    let iam = IamClient::new(credentials, Region::UsEast1);

    // http://docs.aws.amazon.com/IAM/latest/APIReference/Welcome.html
    let request = GetUserRequest {
        ..Default::default()
    };
    iam.get_user(&request).unwrap();
}
