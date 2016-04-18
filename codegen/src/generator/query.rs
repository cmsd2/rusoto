use inflector::Inflector;

use botocore::{Member, Operation, Service, Shape, ShapeType};
use super::GenerateProtocol;
use super::tests::{Response, find_responses};

pub struct QueryGenerator;

impl GenerateProtocol for QueryGenerator {
    fn generate_methods(&self, service: &Service) -> String {
        service.operations.values().map(|operation| {
            format!(
                "
                {documentation}
                {method_signature} {{
                    let mut request = SignedRequest::new(\"{http_method}\", \"{endpoint_prefix}\", self.region, \"{request_uri}\");
                    let mut params = Params::new();

                    params.put(\"Action\", \"{operation_name}\");
                    params.put(\"Version\", \"{api_version}\");
                    {serialize_input}
                    request.set_params(params);

                    request.sign(&try!(self.credentials_provider.credentials()));
                    let result = try!(self.dispatcher.dispatch(&request));

                    {xml_stack_loader}

                    match result.status {{
                        200 => {{
                            {method_return_value}
                        }}
                        _ => {{
                            Err({error_type}::from_body(&result.body))
                        }}
                    }}
                }}
                ",
                api_version = &service.metadata.api_version,
                documentation = generate_documentation(operation),
                error_type = operation.error_type_name(),
                http_method = &operation.http.method,
                endpoint_prefix = &service.metadata.endpoint_prefix,
                method_return_value = generate_method_return_value(operation),
                method_signature = generate_method_signature(operation),
                operation_name = &operation.name,
                xml_stack_loader = generate_xml_stack_loader(&operation.output_shape_or("()")),
                request_uri = &operation.http.request_uri,
                serialize_input = generate_method_input_serialization(operation),
            )
        }).collect::<Vec<String>>().join("\n")
    }

    fn generate_prelude(&self, _: &Service) -> String {
        "use std::collections::HashMap;
        use std::str::{FromStr, from_utf8};
        use xml::EventReader;
        use xml::reader::ParserConfig;

        use param::{Params, ServiceParams};
        use signature::SignedRequest;
        use xmlutil::{Next, Peek, XmlParseError, XmlResponse};
        use xmlutil::{characters, end_element, peek_at_name, start_element};
        use xmlerror::*;
        ".to_owned()
    }

    fn generate_struct_attributes(&self) -> String {
        "#[derive(Debug, Default, Clone)]".to_owned()
    }

    fn generate_support_types(&self, name: &str, shape: &Shape, service: &Service) -> Option<String> {
        Some(format!(
            "/// Deserializes `{name}` from XML.
            struct {name}Deserializer;
            impl {name}Deserializer {{
                fn deserialize<'a, T: Peek + Next>(tag_name: &str, stack: &mut T)
                -> Result<{name}, XmlParseError> {{
                    {deserializer_body}
                }}
            }}

            /// Serialize `{name}` contents to a `SignedRequest`.
            struct {name}Serializer;
            impl {name}Serializer {{
                {serializer_signature} {{
                    {serializer_body}
                }}
            }}
            ",
            deserializer_body = generate_deserializer_body(name, shape, service),
            name = name,
            serializer_body = generate_serializer_body(shape),
            serializer_signature = generate_serializer_signature(name, shape),
        ))
    }

    fn generate_tests(&self, service: &Service) -> Option<String> {
        Some(format!(
            "
            #[cfg(test)]
            mod protocol_tests {{
                {tests_body}
            }}
            ",
            tests_body = generate_tests_body(service)
        ))
    }

    fn timestamp_type(&self) -> &'static str {
        "String"
    }
}

fn generate_documentation(operation: &Operation) -> String {
    match operation.documentation {
        Some(ref docs) => format!("#[doc=\"{}\"]", docs.replace("\"", "\\\"")),
        None => "".to_owned(),
    }
}

fn generate_method_input_serialization(operation: &Operation) -> String {
    if operation.input.is_some() {
        format!(
            "{input_type}Serializer::serialize(&mut params, \"\", &input);",
            input_type = operation.input.as_ref().unwrap().shape,
        )
    } else {
        String::new()
    }
}

fn generate_method_return_value(operation: &Operation) -> String {
    if operation.output.is_some() {
        format!(
            "Ok(try!({output_type}Deserializer::deserialize(\"{output_type}\", &mut stack)))",
            output_type = &operation.output.as_ref().unwrap().shape,
        )
    } else {
        "Ok(())".to_owned()
    }
}

fn generate_method_signature(operation: &Operation) -> String {
    if operation.input.is_some() {
        format!(
            "pub fn {operation_name}(&self, input: &{input_type}) -> Result<{output_type}, {error_type}>",
            input_type = operation.input.as_ref().unwrap().shape,
            operation_name = operation.name.to_snake_case(),
            output_type = &operation.output_shape_or("()"),
            error_type = operation.error_type_name(),
        )
    } else {
        format!(
            "pub fn {operation_name}(&self) -> Result<{output_type}, {error_type}>",
            operation_name = operation.name.to_snake_case(),
            output_type = &operation.output_shape_or("()"),
            error_type = operation.error_type_name(),
        )
    }
}

fn generate_xml_stack_loader(output_type: &str) -> String {
    if output_type == "()" {
        "".to_owned()
    } else {
        format!(
            "let mut reader = EventReader::with_config(
                result.body.as_bytes(),
                ParserConfig::new().trim_whitespace(true)
            );
            let mut stack = XmlResponse::new(reader.events().peekable());

            // Look through the stack for the `StartElement` `XmlEvent` for the
            // `{output_type}`. This is necessary so that we being deserializing at the
            // correct tag in the XML. This loop continues until we either encounter an
            // error or the end of the stack.
            while let Ok(name) = peek_at_name(&mut stack) {{
                if name == \"{output_type}\" || stack.peek() == None {{
                    break;
                }}

                stack.next();
            }}",
            output_type = output_type,
        )
    }
}

fn generate_deserializer_body(name: &str, shape: &Shape, service: &Service) -> String {
    match shape.shape_type {
        ShapeType::List => generate_list_deserializer(shape),
        ShapeType::Map => generate_map_deserializer(shape),
        ShapeType::Structure => generate_struct_deserializer(name, shape, service),
        _ => generate_primitive_deserializer(shape),
    }
}

fn generate_list_deserializer(shape: &Shape) -> String {
    format!(
        "
        let mut obj = vec![];

        while try!(peek_at_name(stack)) == tag_name {{
            obj.push(try!({member_name}Deserializer::deserialize(tag_name, stack)));
        }}

        Ok(obj)
        ",
        member_name = shape.member()
    )
}

fn generate_map_deserializer(shape: &Shape) -> String {
    let key = shape.key.as_ref().unwrap();
    let value = shape.value.as_ref().unwrap();

    format!(
        "
        let mut obj = HashMap::new();

        while try!(peek_at_name(stack)) == tag_name {{
            try!(start_element(tag_name, stack));
            let key = try!({key_type_name}Deserializer::deserialize(\"{key_tag_name}\", stack));
            let value = try!({value_type_name}Deserializer::deserialize(\"{value_tag_name}\", stack));
            obj.insert(key, value);
            try!(end_element(tag_name, stack));
        }}

        Ok(obj)
        ",
        key_tag_name = key.tag_name(),
        key_type_name = key.shape,
        value_tag_name = value.tag_name(),
        value_type_name = value.shape,
    )
}

fn generate_primitive_deserializer(shape: &Shape) -> String {
    let statement =  match shape.shape_type {
        ShapeType::String | ShapeType::Timestamp => "try!(characters(stack))",
        ShapeType::Integer => "i32::from_str(try!(characters(stack)).as_ref()).unwrap()",
        ShapeType::Double => "f32::from_str(try!(characters(stack)).as_ref()).unwrap()",
        ShapeType::Blob => "try!(characters(stack)).into_bytes()",
        ShapeType::Boolean => "bool::from_str(try!(characters(stack)).as_ref()).unwrap()",
        shape_type => panic!("Unknown primitive shape type: {:?}", shape_type),
    };

    format!(
        "try!(start_element(tag_name, stack));
        let obj = {statement};
        try!(end_element(tag_name, stack));

        Ok(obj)
        ",
        statement = statement,
    )
}

fn generate_struct_deserializer(name: &str, shape: &Shape, service: &Service) -> String {
    if shape.members.as_ref().unwrap().is_empty() {
        return format!(
            "try!(start_element(tag_name, stack));

            let obj = {name}::default();

            try!(end_element(tag_name, stack));

            Ok(obj)
            ",
            name = name,
        );
    }

    format!(
        "try!(start_element(tag_name, stack));

        let mut obj = {name}::default();

        loop {{
            match &try!(peek_at_name(stack))[..] {{
                {struct_field_deserializers}
                _ => break,
            }}
        }}

        try!(end_element(tag_name, stack));

        Ok(obj)
        ",
        name = name,
        struct_field_deserializers = generate_struct_field_deserializers(shape, service),
    )
}

fn generate_struct_field_deserializers(shape: &Shape, service: &Service) -> String {
    shape.members.as_ref().unwrap().iter().map(|(member_name, member)| {
        // look up member.shape in all_shapes.  use that shape.member.location_name
        let mut location_name = member_name.to_string();
        let mut member_loc_name = "".to_string();
        if member.location_name.is_some() {
            member_loc_name = member.location_name.clone().unwrap().to_string();
        }

        let parse_expression_location_name = if let Some(ref child_shape) = service.shape_for_member(member) {
            if child_shape.flattened.is_some() {
                if let Some(ref child_member) = child_shape.member {
                    if let Some(ref loc_name) = child_member.location_name {
                        location_name = loc_name.to_string();
                        Some(&location_name)
                    } else {
                        None
                    }
                } else {
                    // assumes we'll only hit this case if a location_name is provided
                    Some(&member_loc_name)
                }
            } else {
                None
            }
        } else {
            None
        };

        let parse_expression = generate_struct_field_parse_expression(shape, member_name, member, parse_expression_location_name);
        format!(
            "\"{location_name}\" => {{
                obj.{field_name} = {parse_expression};
                continue;
            }}",
            field_name = member_name.to_snake_case(),
            parse_expression = parse_expression,
            location_name = parse_expression_location_name.unwrap_or(&location_name),
        )

    }).collect::<Vec<String>>().join("\n")
}

fn generate_struct_field_parse_expression(
    shape: &Shape,
    member_name: &str,
    member: &Member,
    location_name: Option<&String>,
) -> String {

    let location_to_use = match location_name {
        Some(loc) => loc.to_string(),
        None => member_name.to_string(),
    };
    let expression = format!(
        "try!({name}Deserializer::deserialize(\"{location}\", stack))",
        name = member.shape,
        location = location_to_use,
    );

    if shape.required(member_name) {
        expression
    } else {
        format!("Some({})", expression)
    }
}

fn generate_serializer_body(shape: &Shape) -> String {
    match shape.shape_type {
        ShapeType::List => generate_list_serializer(shape),
        ShapeType::Map => generate_map_serializer(shape),
        ShapeType::Structure => generate_struct_serializer(shape),
        _ => generate_primitive_serializer(shape),
    }
}

fn generate_serializer_signature(name: &str, shape: &Shape) -> String {
    if shape.shape_type == ShapeType::Structure && shape.members.as_ref().unwrap().is_empty() {
        format!("fn serialize(_params: &mut Params, name: &str, _obj: &{})", name)
    } else {
        format!("fn serialize(params: &mut Params, name: &str, obj: &{})", name)
    }
}

fn generate_list_serializer(shape: &Shape) -> String {
    format!(
        "for (index, element) in obj.iter().enumerate() {{
    // Lists are one-based, see example here: http://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
    let key = format!(\"{{}}.{{}}\", name, index+1);
    {name}Serializer::serialize(params, &key, element);
}}
        ",
        name = shape.member(),
    )
}

fn generate_map_serializer(shape: &Shape) -> String {
    format!(
        "for (index, (key, value)) in obj.iter().enumerate() {{
    let prefix = format!(\"{{}}.{{}}\", name, index);
    {key_name}Serializer::serialize(
        params,
        &format!(\"{{}}.{{}}\", prefix, \"{key_name}\"),
        key,
    );
    {value_name}Serializer::serialize(
        params,
        &format!(\"{{}}.{{}}\", prefix, \"{value_name}\"),
        value,
    );
}}
        ",
        key_name = shape.key(),
        value_name = shape.value(),
    )
}

fn generate_struct_serializer(shape: &Shape) -> String {
    format!(
        "let mut prefix = name.to_string();
if prefix != \"\" {{
    prefix.push_str(\".\");
}}

{struct_field_serializers}
        ",
        struct_field_serializers = generate_struct_field_serializers(shape),
    )
}

fn generate_struct_field_serializers(shape: &Shape) -> String {
    shape.members.as_ref().unwrap().iter().map(|(member_name, member)| {
        if shape.required(member_name) {
            format!(
                "{member_shape_name}Serializer::serialize(
    params,
    &format!(\"{{}}{{}}\", prefix, \"{tag_name}\"),
    &obj.{field_name},
);
                ",
                field_name = member_name.to_snake_case(),
                member_shape_name = member.shape,
                tag_name = member_name,
            )
        } else {
            format!(
                "if let Some(ref field_value) = obj.{field_name} {{
    {member_shape_name}Serializer::serialize(
        params,
        &format!(\"{{}}{{}}\", prefix, \"{tag_name}\"),
        field_value,
    );
}}
                ",
                field_name = member_name.to_snake_case(),
                member_shape_name = member.shape,
                tag_name = member.tag_name(),
            )
        }
    }).collect::<Vec<String>>().join("\n")
}

fn generate_primitive_serializer(shape: &Shape) -> String {
    let expression = match shape.shape_type {
        ShapeType::String | ShapeType::Timestamp => "obj",
        ShapeType::Integer | ShapeType::Double | ShapeType::Boolean => "&obj.to_string()",
        ShapeType::Blob => "from_utf8(obj).unwrap()",
        shape_type => panic!("Unknown primitive shape type: {:?}", shape_type),
    };

    format!("params.put(name, {});", expression)
}

fn generate_response_parse_test(service: &Service, response: Response) -> Option<String> {
    let maybe_operation = service.operations.get(&response.action);

    if maybe_operation.is_none() {
        return None;
    }

    let operation = maybe_operation.unwrap();
    let input_shape = operation.input_shape();

    Some(format!("
    #[test]
    fn test_parse_{service_name}_{action}() {{
        let mock_response =  MockResponseReader::read_response(\"{response_file_name}\");

        let mock = MockRequestDispatcher::with_status(200)
            .with_body(&mock_response);

        let client = {client_type}::with_request_dispatcher(mock, MockCredentialsProvider, Region::UsEast1);

        let request = {request_type}::default();

        let result = client.{action_method}(&request);

        assert!(result.is_ok());
    }}
    ",
    service_name=response.service.to_snake_case(),
    action=response.action.to_snake_case(),
    response_file_name=response.file_name,
    client_type=service.client_type_name(),
    request_type=input_shape,
    action_method=operation.name.to_snake_case()))
}

fn generate_tests_body(service: &Service) -> String {
    let responses: Vec<Response> = find_responses();

    let our_responses: Vec<Response> = responses
        .into_iter()
        .filter(|r| r.service == service.service_type_name())
        .collect();

    let test_bodies: Vec<String> = our_responses
        .into_iter()
        .flat_map(|response| generate_response_parse_test(service, response))
        .collect();

    let tests_str = test_bodies
        .join("\n\n");

    format!("
        use mock::*;
        use super::*;
        use super::super::Region;

        {test_bodies}
    ",
    test_bodies=tests_str)
}
