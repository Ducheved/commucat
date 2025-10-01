use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};

/// Lazily computed OpenAPI document.
static OPENAPI_JSON: OnceLock<String> = OnceLock::new();

/// Returns the OpenAPI specification as a JSON string.
pub fn openapi_json() -> &'static str {
    OPENAPI_JSON.get_or_init(|| {
        ApiDoc::openapi()
            .to_pretty_json()
            .unwrap_or_else(|_| "{}".to_string())
    })
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "CommuCat Secure Messaging Server API",
        version = "1.0.0",
        description = r#"REST API для защищённого P2P-мессенджера."#
    ),
    servers(
        (
            url = "https://{domain}",
            description = "Production server",
            variables(("domain" = (default = "commucat.example.org")))
        ),
        (url = "http://localhost:8443", description = "Local development")
    ),
    security(("BearerAuth" = [])),
    components(
        schemas(
            ProblemDetails,
            FriendEntry,
            FriendsGetResponse,
            FriendsPutRequest,
            FriendDeviceSnapshot,
            FriendDevicesResponse,
            FriendRequest,
            FriendRequestCreate,
            FriendRequestsListResponse,
            FriendRequestResponse,
            ServerInfoResponse,
            NoiseKeyDescriptor,
            PairingInfo
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Server Info", description = "Информация о сервере и настройках"),
        (name = "Friends", description = "Список друзей")
    ),
    paths(
        server_info_endpoint,
        friends_get_endpoint,
        friends_put_endpoint,
        friend_devices_endpoint,
        friend_request_create_endpoint,
        friend_requests_list_endpoint,
        friend_request_accept_endpoint,
        friend_request_reject_endpoint,
        friend_delete_endpoint
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        let scheme = SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("Session Token")
                .description(Some("Session token полученный после Noise handshake"))
                .build(),
        );
        components.add_security_scheme("BearerAuth", scheme);
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ProblemDetails {
    #[schema(example = "about:blank")]
    pub r#type: String,
    #[schema(example = "BadRequest")]
    pub title: String,
    #[schema(example = 400)]
    pub status: i32,
    #[schema(nullable = true, example = "friend.user_id is required")]
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendEntry {
    #[schema(example = "user-abc123")]
    pub user_id: String,
    #[schema(nullable = true, example = "Alice from Org B")]
    pub alias: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendDeviceSnapshot {
    #[schema(example = "device-xyz")]
    pub device_id: String,
    #[schema(example = "aabbccdd")]
    pub public_key: String,
    #[schema(example = "active")]
    pub status: String,
    #[schema(format = DateTime, example = "2024-03-17T12:00:00Z")]
    pub created_at: String,
    #[schema(nullable = true, format = DateTime, example = "2024-04-01T00:00:00Z")]
    pub last_rotated_at: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendsGetResponse {
    pub friends: Vec<FriendEntry>,
    pub devices: BTreeMap<String, Vec<FriendDeviceSnapshot>>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendsPutRequest {
    #[schema(max_items = 512)]
    pub friends: Vec<FriendEntry>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendDevicesResponse {
    #[schema(example = "user-abc123")]
    pub friend: String,
    pub devices: Vec<FriendDeviceSnapshot>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendRequest {
    #[schema(example = "req-xyz789")]
    pub id: String,
    #[schema(example = "user-alice")]
    pub from_user_id: String,
    #[schema(example = "user-bob")]
    pub to_user_id: String,
    #[schema(example = "pending")]
    pub status: String, // 'pending', 'accepted', 'rejected'
    #[schema(nullable = true, example = "Let's be friends!")]
    pub message: Option<String>,
    #[schema(format = DateTime, example = "2024-03-17T12:00:00Z")]
    pub created_at: String,
    #[schema(format = DateTime, example = "2024-03-17T12:05:00Z")]
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendRequestCreate {
    #[schema(
        nullable = true,
        max_length = 500,
        example = "Hi! I'd like to add you as a friend"
    )]
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendRequestsListResponse {
    pub incoming: Vec<FriendRequest>,
    pub outgoing: Vec<FriendRequest>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FriendRequestResponse {
    pub request: FriendRequest,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NoiseKeyDescriptor {
    pub version: i64,
    #[schema(example = "aabbccddeeff")]
    pub public: String,
    #[schema(format = DateTime, example = "2024-03-01T10:00:00Z")]
    pub valid_after: String,
    #[schema(format = DateTime, example = "2024-03-15T10:00:00Z")]
    pub rotates_at: String,
    #[schema(format = DateTime, example = "2024-05-01T10:00:00Z")]
    pub expires_at: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PairingInfo {
    pub auto_approve: bool,
    #[schema(example = 600)]
    pub pairing_ttl: i64,
    #[schema(example = 4)]
    pub max_auto_devices: i64,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ServerInfoResponse {
    #[schema(example = "commucat.example.org")]
    pub domain: String,
    #[schema(example = "bbccddeeff")]
    pub noise_public: String,
    pub noise_keys: Vec<NoiseKeyDescriptor>,
    #[schema(example = "aabbccdd")]
    pub device_ca_public: String,
    pub supported_patterns: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub pairing: PairingInfo,
}

#[derive(IntoParams)]
#[allow(dead_code)]
pub struct FriendDevicesParams {
    #[param(example = "user-abc123")]
    pub user_id: String,
}

#[derive(IntoParams)]
#[allow(dead_code)]
pub struct FriendRequestParams {
    #[param(example = "user-bob")]
    pub user_id: String,
}

#[derive(IntoParams)]
#[allow(dead_code)]
pub struct DeleteFriendParams {
    #[param(example = "user-alice")]
    pub user_id: String,
}

// Note: These functions are markers for OpenAPI generation and are not called directly
#[allow(dead_code)]
#[utoipa::path(
    get,
    path = "/api/server-info",
    tag = "Server Info",
    responses(
        (status = 200, description = "Server info", body = ServerInfoResponse),
        (status = 500, description = "Internal error", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn server_info_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    get,
    path = "/api/friends",
    tag = "Friends",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, description = "Friends list", body = FriendsGetResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friends_get_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    put,
    path = "/api/friends",
    tag = "Friends",
    security(("BearerAuth" = [])),
    request_body(content = FriendsPutRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Friends updated", body = FriendsGetResponse),
        (status = 400, description = "Bad request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friends_put_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    get,
    path = "/api/friends/{user_id}/devices",
    tag = "Friends",
    security(("BearerAuth" = [])),
    params(FriendDevicesParams),
    responses(
        (status = 200, description = "Friend devices", body = FriendDevicesResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Friend not found", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friend_devices_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    post,
    path = "/api/friends/requests/{user_id}",
    tag = "Friends",
    security(("BearerAuth" = [])),
    params(FriendRequestParams),
    request_body(content = FriendRequestCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "Friend request created", body = FriendRequestResponse),
        (status = 400, description = "Bad request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Request already exists", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friend_request_create_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    get,
    path = "/api/friends/requests",
    tag = "Friends",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, description = "Friend requests list", body = FriendRequestsListResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friend_requests_list_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    post,
    path = "/api/friends/requests/{user_id}/accept",
    tag = "Friends",
    security(("BearerAuth" = [])),
    params(FriendRequestParams),
    responses(
        (status = 200, description = "Friend request accepted", body = FriendRequestResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Request not found", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friend_request_accept_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    post,
    path = "/api/friends/requests/{user_id}/reject",
    tag = "Friends",
    security(("BearerAuth" = [])),
    params(FriendRequestParams),
    responses(
        (status = 200, description = "Friend request rejected", body = FriendRequestResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Request not found", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friend_request_reject_endpoint() {}

#[allow(dead_code)]
#[utoipa::path(
    delete,
    path = "/api/friends/{user_id}",
    tag = "Friends",
    security(("BearerAuth" = [])),
    params(DeleteFriendParams),
    responses(
        (status = 204, description = "Friend deleted"),
        (status = 401, description = "Unauthorized", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Friend not found", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub fn friend_delete_endpoint() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_contains_expected_paths() {
        let doc = ApiDoc::openapi();
        let json = doc.to_json().expect("serialize openapi");
        assert!(json.contains("/api/friends"));
        assert!(json.contains("/api/server-info"));
    }
}
