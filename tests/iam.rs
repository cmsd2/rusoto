#![cfg(feature = "iam")]

extern crate rusoto;

use rusoto::iam::IamClient;
use rusoto::iam::{GetUserRequest, GetUserError};
use rusoto::{DefaultCredentialsProvider, Region};

#[test]
fn main() {
    let credentials = DefaultCredentialsProvider::new().unwrap();

    let iam = IamClient::new(credentials, Region::UsEast1);

    // http://docs.aws.amazon.com/IAM/latest/APIReference/Welcome.html
    match iam.get_user(&GetUserRequest{
            ..Default::default()
        }) {
        err =>
            panic!("error: {:?}", err)
    }
}
