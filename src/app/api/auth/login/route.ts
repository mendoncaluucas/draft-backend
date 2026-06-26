// src/app/api/auth/login/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// AppSec: O schema de login não dá dicas sobre o tamanho mínimo da senha para não ajudar atacantes
const loginSchema = z.object({
  email: z.string().email("Formato de e-mail inválido"),
  password: z.string().min(1, "A senha é obrigatória"),
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const parsedData = loginSchema.parse(body);

    // AppSec: Coleta forense para a trilha de auditoria (IP de origem e User-Agent)
    const ipAddress = request.headers.get("x-forwarded-for") || "127.0.0.1";
    const userAgent = request.headers.get("user-agent") || "Desconhecido";

    // 1. Busca o usuário no banco
    const user = await prisma.user.findUnique({
      where: { email: parsedData.email },
    });

    // AppSec: Retorno genérico para prevenir User Enumeration
    if (!user) {
      // AppSec: registra a tentativa falha (e-mail inexistente) — detecção de brute-force
      await prisma.auditLog.create({
        data: {
          action: "LOGIN_FAILED",
          userId: null,
          details: `Tentativa de login para e-mail inexistente: ${parsedData.email}`,
          ipAddress,
          userAgent,
        },
      });
      return NextResponse.json({ error: "Credenciais inválidas" }, { status: 401 });
    }

    // 2. Compara a senha informada com o hash salvo no banco
    const passwordMatch = await bcrypt.compare(parsedData.password, user.passwordHash);

    if (!passwordMatch) {
      // AppSec: registra a tentativa falha (senha incorreta) — detecção de brute-force
      await prisma.auditLog.create({
        data: {
          action: "LOGIN_FAILED",
          userId: user.id,
          details: "Senha incorreta",
          ipAddress,
          userAgent,
        },
      });
      return NextResponse.json({ error: "Credenciais inválidas" }, { status: 401 });
    }

    // 3. Monta o payload seguro do usuário (NUNCA retornar o passwordHash)
    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    // AppSec: registra o login bem-sucedido na trilha forense
    await prisma.auditLog.create({
      data: {
        action: "LOGIN",
        userId: user.id,
        ipAddress,
        userAgent,
      },
    });

    return NextResponse.json({ data: safeUser }, { status: 200 });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno do servidor" }, { status: 500 });
  }
}