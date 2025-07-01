import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ThrottlerGuard } from '@nestjs/throttler';
import { Mailtrap } from './service/mailtrap.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { VerificationLink } from 'src/lib/verificationLink.service';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    Mailtrap,
    VerificationLink,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AuthModule {}
