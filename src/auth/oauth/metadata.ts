export function protectedResourceMetadata(env: Env) {
	return { resource: env.PDS_URL, authorization_servers: [env.PDS_URL], bearer_methods_supported: ["header"], scopes_supported: ["atproto", "transition:generic", "transition:email", "transition:chat.bsky"] };
}

export function authorizationServerMetadata(env: Env) {
	const issuer = env.PDS_URL;
	return {
		issuer,
		authorization_endpoint: `${issuer}/oauth/authorize`,
		token_endpoint: `${issuer}/oauth/token`,
		pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
		revocation_endpoint: `${issuer}/oauth/revoke`,
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		code_challenge_methods_supported: ["S256"],
		token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
		token_endpoint_auth_signing_alg_values_supported: ["ES256"],
		scopes_supported: ["atproto", "transition:generic", "transition:email", "transition:chat.bsky"],
		authorization_response_iss_parameter_supported: true,
		dpop_signing_alg_values_supported: ["ES256"],
		require_pushed_authorization_requests: true,
		client_id_metadata_document_supported: true,
		require_request_uri_registration: true,
	};
}
