// src/lib/auth.ts
import { decode } from "@auth/core/jwt";

// salt = nome do cookie de sessão do NextAuth v5 (em produção HTTPS: "__Secure-authjs.session-token")
const SESSION_COOKIE_SALT = "authjs.session-token";

// AppSec: extrai e valida o Bearer Token (JWT de sessão do NextAuth v5) do cabeçalho Authorization.
export async function authenticate(request: Request) {
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  try {
    return await decode({
      token: authHeader.split(" ")[1],
      secret: process.env.AUTH_SECRET!,
      salt: SESSION_COOKIE_SALT,
    });
  } catch {
    return null;
  }
}

// AppSec: coleta forense para a trilha de auditoria (IP de origem + User-Agent).
export function getForensics(request: Request) {
  return {
    ipAddress: request.headers.get("x-forwarded-for") || "127.0.0.1",
    userAgent: request.headers.get("user-agent") || "Desconhecido",
  };
}
