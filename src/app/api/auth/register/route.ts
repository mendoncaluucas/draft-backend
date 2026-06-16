// app/api/auth/register/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// AppSec: Validação de dados no servidor usando Zod para prevenir injeção de dados malformados [cite: 100, 177]
const registerSchema = z.object({
  name: z.string().min(2, "Nome deve ter pelo menos 2 caracteres"),
  email: z.string().email("Formato de e-mail inválido"),
  password: z.string().min(8, "A senha deve ter no mínimo 8 caracteres"),
  role: z.enum(["COLABORADOR", "ANALISTA", "ADMINISTRADOR"]).default("COLABORADOR") // Validação do Enum que contorna a limitação do SQLite
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    
    // Valida os dados de entrada contra o schema do Zod [cite: 100]
    const parsedData = registerSchema.parse(body);

    // Verifica se o e-mail já existe na base de dados
    const existingUser = await prisma.user.findUnique({
      where: { email: parsedData.email }
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "E-mail já cadastrado." },
        { status: 409 }
      );
    }

    // AppSec: Armazenamento seguro de senhas gerando o hash com salt (nunca texto puro) [cite: 76, 111, 176]
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(parsedData.password, salt);

    // Persistência no banco usando Prisma 
    const newUser = await prisma.user.create({
      data: {
        name: parsedData.name,
        email: parsedData.email,
        passwordHash,
        role: parsedData.role,
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      }
    });

    // AppSec: Opcional registrar a criação de usuário no AuditLog aqui, se a criação for feita por um administrador [cite: 300]
    // Neste exemplo inicial, focamos apenas na rota pública de registro para popular o banco.

    return NextResponse.json({ data: newUser }, { status: 201 });

  } catch (error) {
    if (error instanceof z.ZodError) {
      // Retorna erros de validação com status 400 Bad Request detalhando os campos [cite: 177]
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno do servidor" }, { status: 500 });
  }
}