// src/app/api/documents/[id]/reject/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import { PrismaClient } from "@prisma/client";
import { authenticate, getForensics } from "@/lib/auth";

const prisma = new PrismaClient();

const rejectSchema = z.object({
  reason: z.string().min(3, "Informe o motivo da rejeição (mínimo 3 caracteres)"),
});

// PATCH /api/documents/:id/reject — ANALISTA/ADMINISTRADOR rejeita um documento EM_REVISAO (com motivo).
export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    // AppSec: RBAC — só ANALISTA ou ADMINISTRADOR podem rejeitar
    if (user.role !== "ANALISTA" && user.role !== "ADMINISTRADOR") {
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: `Perfil '${user.role}' tentou rejeitar documento (restrito a ANALISTA/ADMINISTRADOR)`,
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    const { reason } = rejectSchema.parse(await request.json());

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
        data: { status: "REJEITADO" },
      });
      await tx.auditLog.create({
        data: {
          action: "REJECT",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: reason, // motivo da rejeição registrado na trilha forense
          ...getForensics(request),
        },
      });
      return d;
    });

    return NextResponse.json({ data: updated }, { status: 200 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
