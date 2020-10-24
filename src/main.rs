extern crate lambda;
#[macro_use]
extern crate serde;

use lambda::{handler_fn, Context};
use jwks_client::keyset::KeyStore;
use std::time::{SystemTime, UNIX_EPOCH};

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

static JWKS_URL: &str = "A jwks URL";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = handler_fn(handler);
    lambda::run(func).await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeEvent {
    #[serde(rename = "type")]
    event_type: String,
    method_arn: String,
    authorization_token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationResult {
    principal_id: String,
    policy_document: PolicyDocument,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyDocument {
    // Policy document structure's version. Always "2012-10-17" in real AWS.
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Statement")]
    statement: Vec<PolicyStatement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_identifier_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyStatement {
    // string like "execute-api:Invoke"
    #[serde(rename = "Action")]
    action: String,
    // string like "Allow" / "Deny"
    #[serde(rename = "Effect")]
    effect: String,
    // arn string like "arn:aws:execute-api:{regionId}:{accountId}:{apiId}/{stage}/{httpVerb}/[{resource}/[{child-resources}]]"
    #[serde(rename = "Resource")]
    resource: String,
}

// Some of the claims. Check https://www.iana.org/assignments/jwt/jwt.xhtml#claims for full list of registered ones.
#[derive(Deserialize)]
struct JWTClaim {
    iss: String,
    sub: String,
    exp: u64,
    scope: String,
}


async fn handler(event: AuthorizeEvent, _context: Context) -> Result<AuthorizationResult, Error> {
    // Expecting typical "Bearer [some jwt]" for here in this example.
    let jwt = &event.authorization_token[7..];

    let key_set = KeyStore::new_from(JWKS_URL).await.unwrap();
    let jwt_verified = key_set.verify(jwt).map_err(|_| "verification error")?;

    let claims: JWTClaim = jwt_verified.payload().into::<JWTClaim>().map_err(|_| "claim convertion error")?;
    if is_valid(claims)? {
        Ok(generate_allow_result())
    } else {
        Err(From::from("Not good"))
    }
}

fn is_valid(claims: JWTClaim) -> Result<bool, Error> {
    // Scopes should be defined in your auth provider. Using "resource:write", "resource:read" for example.
    let scopes = claims.scope.split_ascii_whitespace();
    let mut has_write = false;
    let mut has_read = false;
    for scope in scopes {
        if scope.eq("resource:write") {
            has_write = true;
        }
        if scope.eq("resource:read") {
            has_read = true;
        }
    }

    Ok(has_write & has_read)
}

fn generate_allow_result() -> AuthorizationResult {
    AuthorizationResult {
        principal_id: "Example".to_string(),
        policy_document: PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![generate_allow_policy()],
            usage_identifier_key: None,
        },
    }
}

fn generate_allow_policy() -> PolicyStatement {
    PolicyStatement {
        action: "execute-api:Invoke".to_string(),
        effect: "Allow".to_string(),
        // Pretty too loose. It's just for an example.
        resource: "arn:aws:execute-api:*:*:*/*/*/*".to_string(),
    }
}