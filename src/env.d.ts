interface Env {
	SIGNING_KEY_WRAPPING_SECRET: string;
	SERVICE_DID: string;
	AVAILABLE_USER_DOMAINS: string;
	BLOB_UPLOAD_LIMIT: string;
	SESSION_JWT_SECRET: string;
	PDS_URL: string;
	PLC_DIRECTORY: string;
	EMAIL_FROM: string;
	EMAIL: SendEmail;
	ADMIN_PASSWORD: string;
	DB: D1Database;
	TEST_D1_MIGRATIONS: { name: string; queries: string[] }[];
	LOGIN_ACCOUNT_RATE: RateLimit;
	LOGIN_IP_RATE: RateLimit;
	CREATE_ACCOUNT_RATE: RateLimit;
	OAUTH_TOKEN_RATE: RateLimit;
	PROXY_RATE: RateLimit;
	BLOBS: R2Bucket;
	ACCOUNT_REPO: DurableObjectNamespace<import("./durable/account-repo").AccountRepo>;
	BLOB_CLEANUP: Queue;
	FIREHOSE: DurableObjectNamespace<import("./durable/firehose").Firehose>;
}
