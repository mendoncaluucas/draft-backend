// src/middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  // Inicializa a resposta
  const response = NextResponse.next();

  // AppSec: Configuração estrita de CORS conforme documentação do projeto
  const allowedOrigin = "http://localhost:3000";

  response.headers.set("Access-Control-Allow-Origin", allowedOrigin);
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.headers.set("Access-Control-Allow-Credentials", "false");

  // O navegador envia uma requisição OPTIONS (Preflight) antes do POST real
  // Precisamos interceptar o OPTIONS e retornar status 200 com os headers
  if (request.method === "OPTIONS") {
    return new NextResponse(null, {
      status: 200,
      headers: response.headers,
    });
  }

  return response;
}

// Aplica este middleware exclusivamente nas rotas da nossa API
export const config = {
  matcher: "/api/:path*",
};