//! Mock request dispatcher and credentials for unit testing services
use super::{DispatchSignedRequest, HttpResponse, HttpDispatchError, SignedRequest};
use super::{ProvideAwsCredentials, CredentialsError, AwsCredentials};
use chrono::{Duration, UTC};

const ONE_DAY: i64 = 86400;

pub struct MockCredentialsProvider;

impl ProvideAwsCredentials for MockCredentialsProvider {
    fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
		Ok(AwsCredentials::new("mock_key", "mock_secret", None, UTC::now() + Duration::seconds(ONE_DAY)))
    }
}

pub struct MockRequestDispatcher {
	mock_response: HttpResponse,
	request_checker: Option<Box<Fn(&SignedRequest)>>
}

impl MockRequestDispatcher {
	pub fn with_status(status: u16) -> MockRequestDispatcher {
		let mut response = HttpResponse::default();
		response.status = status;
		MockRequestDispatcher { 
			mock_response: response,
			request_checker: None
		}
	}

	pub fn with_body(mut self, body: &str) -> MockRequestDispatcher {
		self.mock_response.body = body.to_owned();
		self
	}

	pub fn with_request_checker<F>(mut self, checker: F) -> MockRequestDispatcher where F: Fn(&SignedRequest) + 'static {
		self.request_checker = Some(Box::new(checker));
		self
	}

	pub fn with_header(mut self, key: String, value: String) -> MockRequestDispatcher {
		self.mock_response.headers.insert(key, value);
		self
	}

}

impl DispatchSignedRequest for MockRequestDispatcher {
	fn dispatch(&self, request: &SignedRequest) -> Result<HttpResponse, HttpDispatchError> {
		if self.request_checker.is_some() {
			self.request_checker.as_ref().unwrap()(request);
		}
		Ok(self.mock_response.clone())
	}
}