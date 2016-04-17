/// Takes a string and returns it with the first letter capitalized.
pub fn capitalize_first_letter_of_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    out.extend(chars.next().unwrap().to_uppercase());
    out.push_str(chars.as_str());
    out
}
