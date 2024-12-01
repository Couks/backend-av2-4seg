import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthModule } from './controllers/auth/auth.module';
import { UserModule } from './controllers/user/user.module';
import { TokenModule } from './controllers/token/token.module';
import { SecurityModule } from './controllers/security/security.module';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    PassportModule,
    AuthModule,
    UserModule,
    TokenModule,
    SecurityModule,
  ],
  providers: [JwtStrategy],
  exports: [AuthModule, TokenModule],
})
export class ApiModule {}
