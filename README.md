# 🛡️ Draft - API Segura de Gestão de Documentos (Back-end)

![Next.js](https://img.shields.io/badge/Next.js_14-API_Routes-black?style=for-the-badge&logo=next.js)
![Prisma](https://img.shields.io/badge/Prisma_ORM-Database-2D3748?style=for-the-badge&logo=prisma)
![Zod](https://img.shields.io/badge/Zod-Validation-3068b7?style=for-the-badge&logo=zod)
![Security](https://img.shields.io/badge/AppSec-Security_by_Design-success?style=for-the-badge&logo=springsecurity)

A API RESTful do sistema **Draft** (Projeto P06-B) é a espinha dorsal de validação e persistência para a gestão do ciclo de vida de contratos fictícios [5, 6]. Operando sob uma arquitetura de mitigação *cross-origin*, esta aplicação foi desenvolvida com foco central em **Application Security (AppSec)**, garantindo controle rigoroso de acessos e trilhas de auditoria imutáveis [1, 7].

## 💻 Stack Tecnológica

A infraestrutura foi construída com tecnologias robustas voltadas para a segurança da informação [8]:
*   **Framework:** Next.js 14 (Exclusivamente API Routes) [3].
*   **Persistência (ORM):** Prisma ORM utilizando SQLite em ambiente de desenvolvimento [3].
*   **Validação de Dados:** Zod (Server-side validation de payloads) [9].
*   **Criptografia:** `bcryptjs` para tratamento seguro de credenciais [9].

## 🔒 Features de Segurança (AppSec)

A API não confia na entrada do cliente e possui as seguintes defesas ativas:
*   **Validação Estrita via Zod:** Rejeição imediata (HTTP 400) de qualquer payload malformado ou malicioso antes da interação com o banco de dados [9, 10].
*   **Hash de Senhas:** Aplicação de custo computacional com `bcryptjs` e *salt* dinâmico para garantir que senhas nunca sejam armazenadas em texto puro [9, 11].
*   **Autorização Cross-Origin e JWT Bearer:** Middleware que intercepta e valida criptograficamente os tokens JWT enviados no cabeçalho HTTP, recusando origens e identidades não autorizadas [10, 12].
*   **Trilha Forense (AuditLog):** Todas as mutações no sistema (criação, aprovação, rejeição, deleção) são persistidas nativamente junto com o IP (`x-forwarded-for`) e o `userAgent` do cliente, compondo provas forenses de Não-Repúdio [13-15].

## ⚙️ Variáveis de Ambiente

O projeto exige configurações de segredos estritas (não versionadas no controle de código) [15, 16]. Crie um arquivo `.env` na raiz da pasta com o seguinte formato:

```env
# URL de conexão do Prisma ORM (Exemplo usando SQLite local)
DATABASE_URL="file:./dev.db"

# Chave criptográfica para validação da assinatura do JWT
AUTH_SECRET="sua-chave-super-segura-de-no-minimo-32-caracteres"
🚀 Passo a Passo de Execução
Siga as instruções abaixo para executar a API localmente:
Instalar Dependências: Instale os pacotes e bibliotecas descritos no ecossistema:
Configurar o Banco de Dados: Sincronize a modelagem relacional forense criando as tabelas necessárias:
(Alternativamente, utilize npx prisma db push para empurrar o schema diretamente).
Iniciar o Servidor: Inicie a API garantindo que ela ocupe obrigatoriamente a porta de serviço 3001
:
A API estará operante em http://localhost:3001 aguardando conexões autenticadas.

***
