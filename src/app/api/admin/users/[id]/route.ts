// src/app/api/admin/users/[id]/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import { PrismaClient } from "@prisma/client";
import { authenticate, getForensics } from "@/lib/auth";

const prisma = new PrismaClient();

const updateRoleSchema = z.object({
  role: z.enum(["COLABORADOR", "ANALISTA", "ADMINISTRADOR"]),
});

// DELETE /api/admin/users/:id — exclui um usuário. Restrito a ADMINISTRADOR.
export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    if (user.role !== "ADMINISTRADOR") {
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "USER",
          details: `Perfil '${user.role}' tentou excluir usuário (restrito a ADMINISTRADOR)`,
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    // AppSec: impede o admin de excluir a própria conta
    if (params.id === user.id) {
      return NextResponse.json({ error: "Você não pode excluir a própria conta." }, { status: 400 });
    }

    const alvo = await prisma.user.findUnique({ where: { id: params.id } });
    if (!alvo) {
      return NextResponse.json({ error: "Usuário não encontrado" }, { status: 404 });
    }

    await prisma.$transaction(async (tx) => {
      await tx.user.delete({ where: { id: params.id } });
      await tx.auditLog.create({
        data: {
          action: "DELETE_USER",
          userId: user.id as string,
          targetId: params.id,
          targetType: "USER",
          details: `Usuário excluído: ${alvo.email}`,
          ...getForensics(request),
        },
      });
    });

    return NextResponse.json({ message: "Usuário excluído com sucesso" }, { status: 200 });
  } catch (error) {
    // Prisma P2003: violação de chave estrangeira (usuário tem documentos/logs vinculados)
    if (error && typeof error === "object" && (error as { code?: string }).code === "P2003") {
      return NextResponse.json(
        { error: "Usuário possui documentos ou registros vinculados e não pode ser excluído." },
        { status: 409 }
      );
    }
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}

// PATCH /api/admin/users/:id — altera o perfil (role) de um usuário. Restrito a ADMINISTRADOR.
export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    if (user.role !== "ADMINISTRADOR") {
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "USER",
          details: `Perfil '${user.role}' tentou alterar o perfil de um usuário (restrito a ADMINISTRADOR)`,
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    // AppSec: impede o admin de rebaixar o próprio perfil (evita auto-lockout)
    if (params.id === user.id) {
      return NextResponse.json({ error: "Você não pode alterar o próprio perfil." }, { status: 400 });
    }

    const { role } = updateRoleSchema.parse(await request.json());

    const alvo = await prisma.user.findUnique({ where: { id: params.id } });
    if (!alvo) {
      return NextResponse.json({ error: "Usuário não encontrado" }, { status: 404 });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const u = await tx.user.update({
        where: { id: params.id },
        data: { role },
        select: { id: true, name: true, email: true, role: true, createdAt: true },
      });
      await tx.auditLog.create({
        data: {
          action: "UPDATE_USER",
          userId: user.id as string,
          targetId: params.id,
          targetType: "USER",
          details: `Perfil alterado de '${alvo.role}' para '${role}'`,
          ...getForensics(request),
        },
      });
      return u;
    });

    return NextResponse.json({ data: updated }, { status: 200 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
