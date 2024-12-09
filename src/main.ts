import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { CustomValidationPipe } from './auth/pipes/validation.pipe';
import { SanitizeInterceptor } from './common/interceptors/sanitize.interceptor';
import helmet from 'helmet';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { corsConfig } from './config/cors.config';

// Função principal que inicializa a aplicação NestJS
async function bootstrap() {
  // Cria uma nova instância da aplicação
  const app = await NestFactory.create(AppModule, {
    cors: false, // Desabilita CORS padrão
  });

  // Adiciona middleware Helmet para segurança HTTP
  app.use(helmet());
  // Configuração CORS personalizada
  app.enableCors(corsConfig);

  // Adiciona middleware para preflight requests
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', corsConfig.methods);
    res.header(
      'Access-Control-Allow-Headers',
      corsConfig.allowedHeaders.join(','),
    );
    res.header('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }
    next();
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
