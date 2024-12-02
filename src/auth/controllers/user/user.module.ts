import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { TokenModule } from '../token/token.module';
import { SecurityModule } from '../security/security.module';
import { EncryptionModule } from '../../../common/encryption/encryption.module';
import { JwtModule } from '@nestjs/jwt';
import { AppLogger } from 'src/common/logger/app.logger';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
    TokenModule,
    SecurityModule,
    EncryptionModule,
  ],
  controllers: [UserController],
  providers: [UserService, AppLogger],
  exports: [UserService],
})
export class UserModule {}
