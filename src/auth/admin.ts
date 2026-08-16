import { constantTimeEqual } from "../crypto/constant-time";
import { XrpcError } from "../xrpc/errors";

export async function requireAdmin(request: Request, env: Env) {
	const match = /^Bearer (\S+)$/.exec(request.headers.get("authorization") ?? "");
	if (!match || !env.ADMIN_PASSWORD || !await constantTimeEqual(match[1], env.ADMIN_PASSWORD)) throw new XrpcError(401, "AuthenticationRequired");
}
