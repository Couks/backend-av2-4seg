# Módulo de Autenticação Seguro

## Descrição

Sistema de autenticação robusto desenvolvido com NestJS, oferecendo recursos avançados de segurança e gerenciamento de usuários. O projeto implementa práticas modernas de autenticação, incluindo JWT, autenticação de dois fatores (2FA), e um sistema detalhado de logs de segurança.

## Funcionalidades Principais

- Autenticação JWT com refresh token
- Autenticação de dois fatores (2FA)
- Sistema de recuperação de senha
- Logs detalhados de segurança
- Validação e sanitização de dados
- Proteção contra ataques XSS
- Blacklist de tokens

## Requisitos

- Node.js (v18 ou superior)
- SQLite3
- npm

## Instalação

```bash
# Clonar o repositório
git clone [url-do-repositorio]
cd [nome-do-projeto]

# Instalar dependências
npm install

# Configurar o banco de dados
npm prisma migrate dev
```

## Configuração

1. Crie um arquivo `.env` na raiz do projeto:

```env
DATABASE_URL="file:./dev.db"
JWT_SECRET="sua-chave-secreta-aqui"
ALLOWED_ORIGINS="http://localhost:3000"
```

## Executando o Projeto

```bash
# Desenvolvimento
npm run start:dev

# Produção
npm run build
npm run start:prod
```

O servidor estará disponível em `http://localhost:3001`

## Documentação da API

A documentação completa da API está disponível via Swagger UI em `http://localhost:3001/api/docs`

### Endpoints Disponíveis

#### Autenticação

- `POST /api/login` - Login de usuário
  - Retorna tokens de acesso e refresh
- `POST /api/logout` - Logout (invalidação de token)
- `GET /api/token/refresh` - Renovação de token de acesso
- `POST /api/token/validate` - Validação de token JWT

#### Usuários

- `POST /api/users/register` - Registro de novo usuário
- `POST /api/users/2fa/verify` - Verificação de código 2FA
- `POST /api/users/password/forgot` - Solicitação de reset de senha
- `POST /api/users/password/reset` - Reset de senha

#### Segurança

- `GET /api/security/logs` - Consulta de logs de segurança
  - Suporta filtros por:
    - Ação (LOGIN, LOGOUT, PASSWORD_RESET, etc.)
    - Status (SUCCESS, FAILURE)
    - Data (startDate, endDate)
    - Paginação (page, limit)

## Segurança

O projeto implementa várias camadas de segurança:

1. **Validação de Entrada**

   - Sanitização de dados contra XSS
   - Validação de tipos e formatos
   - Proteção contra injeção

2. **Autenticação**

   - Tokens JWT com refresh
   - Suporte a 2FA
   - Blacklist de tokens revogados

3. **Logs de Segurança**
   - Registro detalhado de atividades
   - Monitoramento de tentativas de acesso
   - Rastreamento de alterações sensíveis

## Testes

```bash
# Testes unitários
npm run test

# Testes e2e
npm run test:e2e

# Cobertura de testes
npm run test:cov
```

## Estrutura do Projeto

```
src/
├── auth/
│   ├── controllers/    # Controladores de autenticação
│   ├── dto/           # Objetos de transferência de dados
│   ├── guards/        # Guards de autenticação
│   ├── interceptors/  # Interceptadores de requisição
│   └── services/      # Serviços de autenticação
├── prisma/            # Configuração e schemas do Prisma
└── main.ts           # Ponto de entrada da aplicação
```

## Contribuindo

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE.md](LICENSE.md) para detalhes.
