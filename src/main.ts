import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { CustomValidationPipe } from './auth/pipes/validation.pipe';
import { SanitizeInterceptor } from './common/interceptors/sanitize.interceptor';
import helmet from 'helmet';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';

// Função principal que inicializa a aplicação NestJS
async function bootstrap() {
  // Cria uma nova instância da aplicação
  const app = await NestFactory.create(AppModule);

  // Adiciona middleware Helmet para segurança HTTP
  app.use(helmet());
  // Configura CORS para permitir requisições de origens específicas
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });

  // Adiciona pipes globais para validação de dados
  app.useGlobalPipes(new CustomValidationPipe());
  // Adiciona interceptor para sanitização de dados
  app.useGlobalInterceptors(new SanitizeInterceptor());
  // Adiciona filtro global para tratamento de exceções
  app.useGlobalFilters(new GlobalExceptionFilter());
  // Configura pipe de validação com opções específicas
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Remove propriedades não decoradas
      transform: true, // Transforma dados recebidos para o tipo correto
      forbidNonWhitelisted: true, // Rejeita propriedades não listadas
    }),
  );

  // Configura o Swagger para documentação da API
  const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('API de Autenticação com recursos de segurança')
    .setVersion('1.0')
    .addTag('Authentication')
    .addBearerAuth()
    .build();

  // Cria documento Swagger com as configurações
  const document = SwaggerModule.createDocument(app, config);

  // Configura a interface Swagger UI
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, // Mantém autorização entre recarregamentos
      displayRequestDuration: true, // Mostra duração das requisições
      filter: true, // Habilita filtro de busca
      showExtensions: true,
      showCommonExtensions: true,
      tryItOutEnabled: true, // Permite testar endpoints
      supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
      defaultModelsExpandDepth: 3, // Profundidade de expansão dos modelos
      defaultModelExpandDepth: 3,
      syntaxHighlight: {
        activate: true,
        theme: 'agate',
      },
    },
    // Personalização visual do Swagger UI
    customCss: `
      .topbar-wrapper img { content: url('https://nestjs.com/img/logo-small.svg'); }
      .swagger-ui .topbar { background-color: #000000; }
      .swagger-ui .info .title { color: #000000; }
      .swagger-ui .btn.authorize { background-color: #007bff; }
      .swagger-ui .btn.authorize svg { fill: #ffffff; }
    `,
    customSiteTitle: 'Auth API Documentation',
    customfavIcon: 'https://nestjs.com/img/logo-small.svg',
  });

  // Inicia o servidor na porta 3001
  await app.listen(3001);
}
bootstrap();
