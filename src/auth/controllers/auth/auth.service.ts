import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { EncryptionService } from '../../encryption/encryption.service';
import { TokenService } from '../token/token.service';
import { SecurityLogService } from '../security/security-log.service';
import { LoginDto } from '../../dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private tokenService: TokenService,
    private securityLogService: SecurityLogService,
  ) {}

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.encryption.comparePasswords(
      dto.password,
      user.password,
    );

    if (!isPasswordValid) {
      await this.securityLogService.logFailedLogin(user.id);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.twoFactorEnabled) {
      return {
        requiresTwoFactor: true,
        tempToken: this.tokenService.generateTempToken(user.id),
      };
    }

    const tokens = await this.tokenService.generateTokenPair(user.id);
    await this.securityLogService.logSuccessfulLogin(user.id);

    return tokens;
  }

  async logout(token: string) {
    await this.tokenService.blacklistToken(token);
    await this.securityLogService.logLogout();
    return { message: 'Logged out successfully' };
  }
}
