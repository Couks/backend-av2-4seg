import { Global, Module } from '@nestjs/common';
import { AppLogger } from './app.logger';
import { SecurityModule } from '../../auth/controllers/security/security.module';

@Global()
@Module({
  imports: [SecurityModule],
  providers: [AppLogger],
  exports: [AppLogger],
})
export class LoggerModule {}
