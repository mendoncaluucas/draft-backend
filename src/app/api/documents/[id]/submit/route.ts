// src/app/api/documents/[id]/submit/route.ts
import { NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { authenticate, getForensics } from "@/lib/auth";

const prisma = new PrismaClient();

// PATCH /api/documents/:id/submit — o dono submete um RASCUNHO para revisão.
export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    const doc = await prisma.document.findUnique({ where: { id: params.id } });
    if (!doc) {
      return NextResponse.json({ error: "Documento não encontrado" }, { status: 404 });
    }

    const isOwner = doc.ownerId === user.id;
    const isAdmin = user.role === "ADMINISTRADOR";

    // Só o dono (ou admin) submete, e somente se estiver em RASCUNHO
    if ((!isOwner && !isAdmin) || doc.status !== "RASCUNHO") {
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: "Tentativa de submeter documento sem permissão ou fora de RASCUNHO",
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado para submissão" }, { status: 403 });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const d = await tx.document.update({
        where: { id: params.id },
        data: { status: "EM_REVISAO" },
      });
      await tx.auditLog.create({
        data: {
          action: "SUBMIT",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
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
