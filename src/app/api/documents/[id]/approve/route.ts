// src/app/api/documents/[id]/approve/route.ts
import { NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { authenticate, getForensics } from "@/lib/auth";

const prisma = new PrismaClient();

// PATCH /api/documents/:id/approve — ANALISTA/ADMINISTRADOR aprova um documento EM_REVISAO.
export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    // AppSec: RBAC — só ANALISTA ou ADMINISTRADOR podem aprovar
    if (user.role !== "ANALISTA" && user.role !== "ADMINISTRADOR") {
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: `Perfil '${user.role}' tentou aprovar documento (restrito a ANALISTA/ADMINISTRADOR)`,
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    const doc = await prisma.document.findUnique({ where: { id: params.id } });
    if (!doc) {
      return NextResponse.json({ error: "Documento não encontrado" }, { status: 404 });
    }
    if (doc.status !== "EM_REVISAO") {
      return NextResponse.json({ error: "Documento não está em revisão" }, { status: 409 });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const d = await tx.document.update({
        where: { id: params.id },
        data: { status: "APROVADO" },
      });
      await tx.auditLog.create({
        data: {
          action: "APPROVE",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: `Documento aprovado: "${doc.title}"`,
          ...getForensics(request),
        },
      });
      return d;
    });

    return NextResponse.json({ data: updated }, { status: 200 });
  } catch {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
