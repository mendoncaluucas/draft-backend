// src/app/api/admin/users/route.ts
import { NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";
import { authenticate, getForensics } from "@/lib/auth";

const prisma = new PrismaClient();

const createUserSchema = z.object({
  name: z.string().min(2, "Nome deve ter pelo menos 2 caracteres"),
  email: z.string().email("Formato de e-mail inválido"),
  password: z.string().min(8, "A senha deve ter no mínimo 8 caracteres"),
  role: z.enum(["COLABORADOR", "ANALISTA", "ADMINISTRADOR"]),
});

// GET /api/admin/users — lista os usuários. Restrito a ADMINISTRADOR.
export async function GET(request: Request) {
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
          targetType: "USER",
          details: `Perfil '${user.role}' tentou listar usuários (restrito a ADMINISTRADOR)`,
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    const users = await prisma.user.findMany({
      select: { id: true, name: true, email: true, role: true, createdAt: true },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json({ data: users }, { status: 200 });
  } catch {
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}

// POST /api/admin/users — cria um usuário. Restrito a ADMINISTRADOR.
export async function POST(request: Request) {
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
          targetType: "USER",
          details: `Perfil '${user.role}' tentou criar usuário (restrito a ADMINISTRADOR)`,
          ...getForensics(request),
        },
      });
      return NextResponse.json({ error: "Acesso negado" }, { status: 403 });
    }

    const parsed = createUserSchema.parse(await request.json());

    const existing = await prisma.user.findUnique({ where: { email: parsed.email } });
    if (existing) {
      return NextResponse.json({ error: "E-mail já cadastrado." }, { status: 409 });
    }

    // AppSec: hash da senha com bcrypt (nunca em texto puro)
    const passwordHash = await bcrypt.hash(parsed.password, await bcrypt.genSalt(10));

    const created = await prisma.$transaction(async (tx) => {
      const novo = await tx.user.create({
        data: { name: parsed.name, email: parsed.email, passwordHash, role: parsed.role },
        select: { id: true, name: true, email: true, role: true, createdAt: true },
      });
      await tx.auditLog.create({
        data: {
          action: "CREATE_USER",
          userId: user.id as string,
          targetId: novo.id,
          targetType: "USER",
          ...getForensics(request),
        },
      });
      return novo;
    });

    return NextResponse.json({ data: created }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: "Erro interno" }, { status: 500 });
  }
}
