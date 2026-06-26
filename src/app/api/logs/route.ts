// src/app/api/logs/route.ts
import { NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { decode } from "@auth/core/jwt";

const prisma = new PrismaClient();

// Helper: Extrai e valida o Bearer Token do cabeçalho (mesmo padrão de /api/documents)
async function authenticate(request: Request) {
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  try {
    return await decode({
      token: authHeader.split(" ")[1],
      secret: process.env.AUTH_SECRET!,
      salt: "authjs.session-token",
    });
  } catch {
    return null;
  }
}

export async function GET(request: Request) {
  try {
    // 1. Autenticação
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    // 2. AppSec: RBAC de servidor. A trilha de auditoria é exclusiva de administradores.
    // Segunda camada de defesa, independente do middleware do front-end.
    if (user.role !== "ADMINISTRADOR") {
      // AppSec: registra a tentativa de acesso negado na própria trilha forense
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetType: "AUDIT_LOG",
          details: `Perfil '${user.role}' tentou acessar a trilha de auditoria (restrito a ADMINISTRADOR)`,
          ipAddress: request.headers.get("x-forwarded-for") || "127.0.0.1",
          userAgent: request.headers.get("user-agent") || "Desconhecido",
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    // 3. Não-Repúdio: retorna a trilha forense com o autor de cada ação
    const logs = await prisma.auditLog.findMany({
      include: {
        user: { select: { name: true, email: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 200,
    });

    return NextResponse.json({ data: logs }, { status: 200 });
  } catch {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
