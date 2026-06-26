// src/app/api/documents/[id]/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import { PrismaClient } from "@prisma/client";
import { decode } from "@auth/core/jwt";

const prisma = new PrismaClient();

// Schema de validação para edição [cite: 279]
const updateSchema = z.object({
  title: z.string().min(3).optional(),
  description: z.string().min(5).optional(),
});

// Helper de autenticação
async function authenticate(request: Request) {
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  try {
    return await decode({
      token: authHeader.split(" ")[1],
      secret: process.env.AUTH_SECRET!,
      salt: "authjs.session-token",
    });
  } catch (error) {
    return null;
  }
}

// Utilitário para coletar dados forenses [cite: 292]
const getForensics = (request: Request) => ({
  ipAddress: request.headers.get("x-forwarded-for") || "127.0.0.1",
  userAgent: request.headers.get("user-agent") || "Desconhecido",
});

export async function GET(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user) return NextResponse.json({ error: "Não autorizado" }, { status: 401 });

    const document = await prisma.document.findUnique({
      where: { id: params.id },
      include: { versions: true, owner: { select: { id: true, name: true } } }, // Inclui histórico de versões [cite: 85]
    });

    if (!document) return NextResponse.json({ error: "Documento não encontrado" }, { status: 404 });

    // AppSec: IDOR Mitigation - Colaborador só acede aos seus [cite: 93, 252]
    if (user.role === "COLABORADOR" && document.ownerId !== user.id) {
      // AppSec: Registra a tentativa de acesso negado na trilha forense
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: "Colaborador tentou acessar documento de outro usuário (IDOR)",
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 }); // Regra demonstrável [cite: 95]
    }

    return NextResponse.json({ data: document }, { status: 200 });
  } catch (error) {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}

export async function PUT(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user) return NextResponse.json({ error: "Não autorizado" }, { status: 401 });

    const document = await prisma.document.findUnique({ where: { id: params.id } });
    if (!document) return NextResponse.json({ error: "Não encontrado" }, { status: 404 });

    // Apenas o dono pode editar, e apenas se for RASCUNHO [cite: 84]
    if (document.ownerId !== user.id || document.status !== "RASCUNHO") {
      // AppSec: Registra a tentativa de edição não autorizada na trilha forense
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: "Tentativa de edição de documento sem permissão (não é dono ou não é RASCUNHO)",
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado para edição" }, { status: 403 });
    }

    const body = await request.json();
    const parsedData = updateSchema.parse(body);
    const forensics = getForensics(request);

    // Transação: Atualiza documento, cria nova versão e regista auditoria [cite: 86, 297]
    const updatedDoc = await prisma.$transaction(async (tx) => {
      const newVersionNumber = document.currentVersion + 1;

      const doc = await tx.document.update({
        where: { id: params.id },
        data: {
          title: parsedData.title,
          description: parsedData.description,
          currentVersion: newVersionNumber,
        },
      });

      await tx.documentVersion.create({
        data: {
          documentId: doc.id,
          versionNumber: newVersionNumber,
          content: parsedData.description || document.description,
          createdById: user.id as string,
        },
      });

      await tx.auditLog.create({
        data: {
          action: "UPDATE_DOC", // Registo exigido de edição 
          userId: user.id as string,
          targetId: doc.id,
          targetType: "DOCUMENT",
          ...forensics,
        },
      });

      return doc;
    });

    return NextResponse.json({ data: updatedDoc }, { status: 200 });
  } catch (error) {
    if (error instanceof z.ZodError) return NextResponse.json({ error: error.issues }, { status: 400 });
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  try {
    const user = await authenticate(request);
    if (!user) return NextResponse.json({ error: "Não autorizado" }, { status: 401 });

    const document = await prisma.document.findUnique({ where: { id: params.id } });
    if (!document) return NextResponse.json({ error: "Não encontrado" }, { status: 404 });

    // Exclusão só é permitida para administradores ou para o dono do rascunho [cite: 170]
    if (user.role !== "ADMINISTRADOR" && (document.ownerId !== user.id || document.status !== "RASCUNHO")) {
      // AppSec: Registra a tentativa de exclusão não autorizada na trilha forense
      await prisma.auditLog.create({
        data: {
          action: "ACCESS_DENIED",
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          details: "Tentativa de exclusão de documento sem permissão",
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado para exclusão" }, { status: 403 });
    }

    const forensics = getForensics(request);

    await prisma.$transaction(async (tx) => {
      await tx.documentVersion.deleteMany({ where: { documentId: params.id } });
      await tx.document.delete({ where: { id: params.id } });
      
      await tx.auditLog.create({
        data: {
          action: "DELETE_DOC", // Registo exigido de exclusão [cite: 299]
          userId: user.id as string,
          targetId: params.id,
          targetType: "DOCUMENT",
          ...forensics,
        },
      });
    });

    return NextResponse.json({ message: "Documento excluído com sucesso" }, { status: 200 });
  } catch (error) {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}