import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { CustomValidationPipe } from './auth/pipes/validation.pipe';
import { SanitizeInterceptor } from './common/interceptors/sanitize.interceptor';
import helmet from 'helmet';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';

// Arquivo principal que configura e inicializa a aplicação
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Configurações de segurança
  app.use(helmet());
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });

  // Pipes e interceptors para validação e sanitização
  app.useGlobalPipes(new CustomValidationPipe());
  app.useGlobalInterceptors(new SanitizeInterceptor());
  app.useGlobalFilters(new GlobalExceptionFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Configuração Swagger
  const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('API de Autenticação com recursos de segurança')
    .setVersion('1.0')
    .addTag('Authentication')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      filter: true,
      showExtensions: true,
      showCommonExtensions: true,
      tryItOutEnabled: true,
      supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
      defaultModelsExpandDepth: 3,
      defaultModelExpandDepth: 3,
      syntaxHighlight: {
        activate: true,
        theme: 'agate',
      },
    },
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

  await app.listen(3001);
}
bootstrap();
