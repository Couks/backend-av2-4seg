import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { EncryptionService } from '../src/auth/encryption/encryption.service';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  let encryptionService: EncryptionService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    prismaService = app.get<PrismaService>(PrismaService);
    encryptionService = app.get<EncryptionService>(EncryptionService);

    await app.init();
  });

  beforeEach(async () => {
    // Limpa o banco de dados antes de cada teste
    await prismaService.securityLog.deleteMany();
    await prismaService.token.deleteMany();
    await prismaService.user.deleteMany();
  });

  describe('/api/users/register (POST)', () => {
    it('should register a new user', () => {
      return request(app.getHttpServer())
        .post('/api/users/register')
        .send({
          email: 'test@example.com',
          password: 'password123',
          name: 'Test User',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty(
            'message',
            'User registered successfully',
          );
        });
    });

    it('should fail with invalid data', () => {
      return request(app.getHttpServer())
        .post('/api/users/register')
        .send({
          email: 'invalid-email',
          password: '123',
          name: '',
        })
        .expect(400);
    });
  });

  describe('/api/login (POST)', () => {
    beforeEach(async () => {
      const hashedPassword =
        await encryptionService.hashPassword('password123');
      await prismaService.user.create({
        data: {
          email: 'test@example.com',
          password: hashedPassword,
          name: 'Test User',
        },
      });
    });

    it('should login successfully', () => {
      return request(app.getHttpServer())
        .post('/api/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('accessToken');
          expect(res.body).toHaveProperty('refreshToken');
        });
    });

    it('should fail with wrong password', () => {
      return request(app.getHttpServer())
        .post('/api/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword',
        })
        .expect(401);
    });
  });

  describe('/api/token/validate (POST)', () => {
    let accessToken: string;

    beforeEach(async () => {
      // Login para obter um token válido
      const response = await request(app.getHttpServer())
        .post('/api/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      accessToken = response.body.accessToken;
    });

    it('should validate a valid token', () => {
      return request(app.getHttpServer())
        .post('/api/token/validate')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.valid).toBe(true);
        });
    });

    it('should fail with invalid token', () => {
      return request(app.getHttpServer())
        .post('/api/token/validate')
        .set('Authorization', 'Bearer invalid.token')
        .expect(200)
        .expect((res) => {
          expect(res.body.valid).toBe(false);
        });
    });
  });

  afterAll(async () => {
    await prismaService.$disconnect();
    await app.close();
  });
});
