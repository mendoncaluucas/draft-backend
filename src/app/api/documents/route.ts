// src/app/api/documents/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import { PrismaClient } from "@prisma/client";
import { decode } from "next-auth/jwt";

const prisma = new PrismaClient();

// AppSec: Validação de dados no servidor usando Zod 
const documentSchema = z.object({
  title: z.string().min(3, "O título deve ter no mínimo 3 caracteres"),
  description: z.string().min(5, "A descrição deve ter no mínimo 5 caracteres"),
});

// Helper de autenticação com logs (espião) e correção do SALT
async function authenticate(request: Request) {
  const authHeader = request.headers.get("authorization");
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("⚠️ Falha de Autenticação: Cabeçalho ausente ou sem 'Bearer '");
    return null;
  }
  
  try {
    const stringDoToken = authHeader.split(" ")[1];
    
    const tokenDecodificado = await decode({
      token: stringDoToken,
      secret: process.env.NEXTAUTH_SECRET!,
      salt: "authjs.session-token", // <-- Adicionado para corrigir o erro fatal de TypeError
    });
    
    console.log("✅ Token decodificado com SUCESSO!", tokenDecodificado);
    return tokenDecodificado;
    
  } catch (error) {
    console.error("🚨 ERRO FATAL AO DESCRIPTOGRAFAR O TOKEN:");
    console.error(error);
    return null;
  }
}

export async function POST(request: Request) {
  try {
    // 1. Autenticação
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    const userId = user.id as string;
    
    // Coleta forense para a trilha de auditoria
    const ipAddress = request.headers.get("x-forwarded-for") || "127.0.0.1";
    const userAgent = request.headers.get("user-agent") || "Desconhecido";

    // 2. Validação do Payload da Requisição
    const body = await request.json();
    const parsedData = documentSchema.parse(body);

    // 3. Transação no Banco
    const result = await prisma.$transaction(async (tx) => {
      
      // A. Cria o documento base
      const newDoc = await tx.document.create({
        data: {
          title: parsedData.title,
          description: parsedData.description,
          status: "RASCUNHO", 
          ownerId: userId,
          currentVersion: 1,
        },
      });

      // B. Cria a primeira versão do documento
      await tx.documentVersion.create({
        data: {
          documentId: newDoc.id,
          versionNumber: 1,
          content: parsedData.description,
          createdById: userId,
        },
      });

      // C. AppSec: Registra a ação na trilha forense
      await tx.auditLog.create({
        data: {
          action: "CREATE_DOC",
          userId: userId,
          targetId: newDoc.id,
          targetType: "DOCUMENT",
          ipAddress: ipAddress,
          userAgent: userAgent,
        },
      });

      return newDoc;
    });

    return NextResponse.json({ data: result }, { status: 201 });

  } catch (error) {
    // CORREÇÃO: O Zod formata o erro de validação exatamente como o Front-end espera receber AQUI no POST!
    if (error instanceof z.ZodError) {
      return NextResponse.json({ 
        error: "Dados inválidos", 
        details: { fieldErrors: error.flatten().fieldErrors } 
      }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}

export async function GET(request: Request) {
  try {
    // 1. Autenticação
    const user = await authenticate(request);
    if (!user || !user.id) {
      return NextResponse.json({ error: "Não autorizado" }, { status: 401 });
    }

    const userId = user.id as string;
    const userRole = user.role as string;

    // AppSec: Autorização por dono do recurso (Mitigação de IDOR/BOLA)
    let whereClause: any = {};
    
    if (userRole === "COLABORADOR") {
      whereClause = { ownerId: userId };
    } else if (userRole === "ANALISTA") {
      whereClause = { status: "EM_REVISAO" }; 
    } 

    const documents = await prisma.document.findMany({
      where: whereClause,
      include: {
        owner: { select: { name: true, email: true } },
      },
      orderBy: { createdAt: 'desc' }
    });

    return NextResponse.json({ data: documents }, { status: 200 });

  } catch (error) {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}