use actix_web::{web, Error, HttpResponse};
use awc::{Client, JsonBody};
use futures::{Async, Future};
use futures_cpupool::CpuPool;
use serde::Serialize;
use serde_derive::Deserialize;
use serde_derive::Serialize as SerDerive;
use serde_json::Value as JsonValue;
use sodiumoxide::crypto::sign::SecretKey;

pub struct FederationData {
    pub cpu_pool: CpuPool,

    pub target_addr: String,
    pub target_name: String,
    pub room_id: String,

    pub server_name: String,
    pub username: String,
    pub secret_key: SecretKey,
    pub key_name: String,

    pub connected: bool,
}

#[derive(SerDerive)]
struct RequestJson {
    method: String,
    uri: String,
    origin: String,
    destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<JsonValue>,
}

#[derive(Debug, Deserialize, SerDerive)]
struct MakeJoinResponse {
    room_version: String,
    event: JsonValue,
}

pub fn deepest(
    (room_id, fd): (web::Path<String>, web::Data<FederationData>),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let client = Client::default();
    let path = format!(
        "/_matrix/federation/v1/make_join/{}/{}",
        room_id,
        percent_encoding::utf8_percent_encode(
            &format!("@{}:{}", fd.username, fd.server_name),
            percent_encoding::USERINFO_ENCODE_SET,
        )
    );

    Box::new(
        client
            .get(&format!("http://{}{}", fd.target_addr, path))
            .header(
                "Authorization",
                request_json(
                    "GET",
                    &fd.server_name,
                    &fd.secret_key,
                    &fd.key_name,
                    &fd.target_name,
                    &path,
                    None,
                ),
            )
            .send()
            .then(move |response| match response {
                Ok(mut res) => {
                    if res.status().is_success() {
                        let mut json = JsonBody::<_, MakeJoinResponse>::new(&mut res).limit(5000);

                        match json.poll() {
                            Ok(json) => match json {
                                Async::Ready(json) => {
                                    let pruned_event = prune_event(
                                        serde_json::to_value(json.event.clone())
                                            .expect("Failed to serialize"),
                                    );

                                    let esig = event_signature(&pruned_event, &fd.secret_key);

                                    let mut event = json.event;

                                    event["signatures"].as_object_mut().unwrap().insert(
                                        fd.server_name.clone(),
                                        json!({ fd.key_name.clone(): esig }),
                                    );

                                    let path = path.as_str().replace("make", "send");

                                    client
                                        .put(&format!("http://{}{}", fd.target_addr, path))
                                        .header(
                                            "Authorization",
                                            request_json(
                                                "PUT",
                                                &fd.server_name,
                                                &fd.secret_key,
                                                &fd.key_name,
                                                &fd.target_name,
                                                &path,
                                                Some(event.clone()),
                                            ),
                                        )
                                        .send_json(&event)
                                        .map_err(|_| ())
                                        .and_then(|response| {
                                            println!("Response: {:?}", response);
                                        }); // FIXME

                                    let response_string = serde_json::to_string(&event)
                                        .expect("Failed to serialize the response object");

                                    HttpResponse::Ok()
                                        .content_type("application/json")
                                        .header("Access-Control-Allow-Origin", "*")
                                        .header("Access-Control-Allow-Methods", "GET, POST")
                                        .header(
                                            "Access-Control-Allow-Headers",
                                            "Origin, X-Requested-With, Content-Type, Accept",
                                        )
                                        .body(response_string)
                                }
                                Async::NotReady => HttpResponse::InternalServerError()
                                    .content_type("application/json")
                                    .header("Access-Control-Allow-Origin", "*")
                                    .header("Access-Control-Allow-Methods", "GET, POST")
                                    .header(
                                        "Access-Control-Allow-Headers",
                                        "Origin, X-Requested-With, Content-Type, Accept",
                                    )
                                    .body("The JSON object wasn't ready"),
                            },
                            Err(e) => HttpResponse::InternalServerError()
                                .content_type("application/json")
                                .header("Access-Control-Allow-Origin", "*")
                                .header("Access-Control-Allow-Methods", "GET, POST")
                                .header(
                                    "Access-Control-Allow-Headers",
                                    "Origin, X-Requested-With, Content-Type, Accept",
                                )
                                .body(&format!("Error with the poll: {}", e)),
                        }
                    } else {
                        HttpResponse::Unauthorized()
                            .content_type("application/json")
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body("Unauthorized by the resident HS")
                    }
                }
                Err(_) => HttpResponse::InternalServerError()
                    .content_type("application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Methods", "GET, POST")
                    .header(
                        "Access-Control-Allow-Headers",
                        "Origin, X-Requested-With, Content-Type, Accept",
                    )
                    .body("Could not send /make_join request"),
            }),
    )
}

pub fn stop() -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body("Stopping the federated backend"),
    ))
}

pub fn serv_cert(_: web::Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    println!("Key requested");

    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .body("The cert of the server"),
    ))
}

fn event_signature(event_object: &JsonValue, signing_key: &SecretKey) -> String {
    let bytes = make_canonical(event_object).expect("Failed make_canonical");
    let signature = sodiumoxide::crypto::sign::ed25519::sign_detached(&bytes, signing_key);
    let base64_signature = base64::encode_config(&signature, base64::STANDARD_NO_PAD);

    base64_signature
}

fn prune_event(event_object: JsonValue) -> JsonValue {
    let etype = event_object["type"].as_str().unwrap();

    let mut content = match event_object["content"].clone() {
        JsonValue::Object(obj) => obj,
        _ => unreachable!(), // Content is always an object
    };

    let allowed_keys = [
        "event_id",
        "sender",
        "room_id",
        "content",
        "type",
        "state_key",
        "depth",
        "prev_events",
        "prev_state",
        "auth_events",
        "origin",
        "origin_server_ts",
        "membership",
    ];

    let val = match event_object.clone() {
        serde_json::Value::Object(obj) => obj,
        _ => unreachable!(), // Events always serialize to an object
    };

    let mut val: serde_json::Map<_, _> = val
        .into_iter()
        .filter(|(k, _)| allowed_keys.contains(&(k as &str)))
        .collect();

    let mut new_content = serde_json::Map::new();

    let mut copy_content = |key: &str| {
        if let Some(v) = content.remove(key) {
            new_content.insert(key.to_string(), v);
        }
    };

    match &etype[..] {
        "m.room.member" => copy_content("membership"),
        "m.room.create" => copy_content("creator"),
        "m.room.join_rules" => copy_content("join_rule"),
        "m.room.aliases" => copy_content("aliases"),
        "m.room.history_visibility" => copy_content("history_visibility"),
        "m.room.power_levels" => {
            for key in &[
                "ban",
                "events",
                "events_default",
                "kick",
                "redact",
                "state_default",
                "users",
                "users_default",
            ] {
                copy_content(key);
            }
        }
        _ => {}
    }

    val.insert(
        "content".to_string(),
        serde_json::Value::Object(new_content),
    );

    serde_json::Value::Object(val)
}

fn request_json(
    method: &str,
    origin_name: &str,
    origin_key: &SecretKey,
    key_name: &str,
    destination: &str,
    path: &str,
    content: Option<JsonValue>,
) -> String {
    let json_to_sign = RequestJson {
        method: method.to_string(),
        uri: path.to_string(),
        origin: origin_name.to_string(),
        destination: destination.to_string(),
        content,
    };

    let bytes = make_canonical(json_to_sign).expect("Failed make_canonical");
    let signature = sodiumoxide::crypto::sign::ed25519::sign_detached(&bytes, origin_key);
    let base64_signature = base64::encode_config(&signature, base64::STANDARD_NO_PAD);

    format!(
        r#"X-Matrix origin={},key="{}",sig="{}""#,
        origin_name, key_name, base64_signature
    )
}

fn make_canonical(s: impl Serialize) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(s)?;
    let uncompact = serde_json::to_vec(&value)?;

    let mut canonical = Vec::with_capacity(uncompact.len());
    indolentjson::compact::compact(&uncompact, &mut canonical).expect("Invalid JSON");

    let canonical = String::from_utf8(canonical).expect("Failed to parse canonical");

    Ok(canonical.into_bytes())
}
