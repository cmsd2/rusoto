use std::fs;
use std::str;
use std::path::Path;
use std::borrow::Borrow;
use std::collections::HashMap;
use includedir::Files;

mod botocore_tests {
    include!(concat!(env!("OUT_DIR"), "/botocore_tests.rs"));
}

mod tests {
    include!(concat!(env!("OUT_DIR"), "/tests.rs"));
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().chain(c).collect(),
    }
}

#[derive(Debug, Clone	)]
pub struct Response {
    pub service: String,
    pub action: String,
    pub file_name: String,
    pub extension: String,
    pub content: String,
}

impl Response {
    pub fn new_for_file(f: &str, content: &str) -> Option<Response> {
        let maybe_file_name_and_extension: Vec<&str> = f.split(".").collect();

        let mut service_name = None;
        let mut action = None;
        let extension = maybe_file_name_and_extension.get(1);

        if let Some(file_name) = maybe_file_name_and_extension.get(0) {
            let file_name_parts: Vec<&str> = file_name.split("-").collect();

            service_name = file_name_parts.get(0).map(|s| capitalise(s));

            action = Some(file_name_parts.into_iter().skip(1).map(|w| capitalise(w)).collect());
        }

        service_name
            .and_then(|s| action
                .and_then(|a| extension
                    .and_then(|e|
                        Some(Response { 
                            service: s, 
                            action: a,
                            file_name: f.to_owned(),
                            extension: e.to_string(),
                            content: content.to_owned(),
                        })
                    )
                )
            )
    }
}

pub fn find_responses_in_files(files: &'static Files) -> Vec<Response> {
    files.file_names()
        
        .map(|f| (Path::new(f).file_name().expect("osstr").to_str().expect("osstr::to_str").to_owned(), 
            str::from_utf8(files.get(f).expect("includdir get").borrow()).expect("str::from_utf8")))
        .flat_map(|(ref f,content)| Response::new_for_file(&f, content))
        .filter(|r| r.extension == "xml")
        .collect()
}

pub fn find_responses() -> HashMap<String, Response> {
    let mut responses = HashMap::new();

    for r in find_responses_in_files(&self::botocore_tests::BOTOCORE_TESTS) {
        responses.insert(r.file_name.clone(), r);
    }

    for r in find_responses_in_files(&self::tests::TESTS) {
        responses.insert(r.file_name.clone(), r);
    }

    responses
}