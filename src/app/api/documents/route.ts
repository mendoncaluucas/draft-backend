// src/app/api/documents/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import { PrismaClient, Prisma } from "@prisma/client";
import { decode } from "@auth/core/jwt";

const prisma = new PrismaClient();

// AppSec: Validação de dados no servidor usando Zod 
const documentSchema = z.object({
  title: z.string().min(3, "O título deve ter no mínimo 3 caracteres"),
  description: z.string().min(5, "A descrição deve ter no mínimo 5 caracteres"),
});

// Helper: Extrai e valida o Bearer Token do cabeçalho [cite: 40, 47]
async function authenticate(request: Request) {
  const authHeader = request.headers.get("authorization");
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.split(" ")[1];
  
  try {
    // Descriptografa e verifica a assinatura do token [cite: 48]
    const decoded = await decode({
      token,
      secret: process.env.AUTH_SECRET!,
      // salt = nome do cookie de sessão do NextAuth v5 (em produção HTTPS: "__Secure-authjs.session-token")
      salt: "authjs.session-token",
    });
    return decoded;
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  try {
    // 1. Autenticação [cite: 45]
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    const userId = user.id as string;
    
    // Coleta forense para a trilha de auditoria [cite: 152, 155, 177]
    const ipAddress = request.headers.get("x-forwarded-for") || "127.0.0.1";
    const userAgent = request.headers.get("user-agent") || "Desconhecido";

    // 2. Validação do Payload da Requisição [cite: 178]
    const body = await request.json();
    const parsedData = documentSchema.parse(body);

    // 3. Transação no Banco: Garante que as 3 inserções ocorram juntas ou falhem juntas
    const result = await prisma.$transaction(async (tx) => {
      
      // A. Cria o documento base [cite: 84]
      const newDoc = await tx.document.create({
        data: {
          title: parsedData.title,
          description: parsedData.description,
          status: "RASCUNHO", // Inicia sempre como rascunho [cite: 87, 122]
          ownerId: userId,
          currentVersion: 1, // [cite: 123]
        },
      });

      // B. Cria a primeira versão do documento [cite: 86]
      await tx.documentVersion.create({
        data: {
          documentId: newDoc.id,
          versionNumber: 1,
          content: parsedData.description,
          createdById: userId,
        },
      });

      // C. AppSec: Registra a ação na trilha forense [cite: 96, 98]
      await tx.auditLog.create({
        data: {
          action: "CREATE_DOC", // [cite: 296]
          userId: userId,
          targetId: newDoc.id,
          targetType: "DOCUMENT", // [cite: 149]
          ipAddress: ipAddress,
          userAgent: userAgent,
        },
      });

      return newDoc;
    });

    return NextResponse.json({ data: result }, { status: 201 });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}

export async function GET(request: Request) {
  try {
    // 1. Autenticação [cite: 45]
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 }); // [cite: 51]
    }

    const userId = user.id as string;
    const userRole = user.role as string;

    // AppSec: Autorização por dono do recurso (Mitigação de IDOR/BOLA) [cite: 93]
    let whereClause: Prisma.DocumentWhereInput = {};
    
    if (userRole === "COLABORADOR") {
      // O Colaborador SÓ enxerga os documentos onde ele é o dono [cite: 93, 169]
      whereClause = { ownerId: userId };
    } else if (userRole === "ANALISTA") {
      // O Analista só vê documentos que foram submetidos para revisão [cite: 169, 171]
      whereClause = { status: "EM_REVISAO" }; 
    } 
    // Se for ADMINISTRADOR, o whereClause continua vazio e ele vê tudo [cite: 169]

    const documents = await prisma.document.findMany({
      where: whereClause,
      include: {
        owner: { select: { name: true, email: true } },
      },
      orderBy: { createdAt: 'desc' }
    });

    return NextResponse.json({ data: documents }, { status: 200 });

  } catch {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}