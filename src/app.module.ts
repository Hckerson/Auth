import { Module } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './models/auth/auth.module';
import { TekcifyModule } from './models/tekcify/tekcify.module';
import appConfig from './config/app/configuration';
import dbConfig from './config/database/configuration';
import emailConfig from './config/email/configuration';
import sessionConfig from './config/session/configuration';

@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig, dbConfig, emailConfig, sessionConfig],
    }),
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60000,
          limit: 10,
        },
      ],
    }),

    TekcifyModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
