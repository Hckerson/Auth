import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ThrottlerGuard } from '@nestjs/throttler';
import { Mailtrap } from './service/mailtrap.service';
import { QrcodeService } from 'src/lib/qr-code.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { SpeakeasyService } from 'src/lib/speakesy.service';
import { VerificationLink } from 'src/lib/verificationLink.service';
import { RiskAssesmentService } from 'src/lib/risk-assesment.service';

@Module({
  controllers: [AuthController],
  providers: [
    Mailtrap,
    AuthService,
    PrismaService,
    QrcodeService,
    VerificationLink,
    SpeakeasyService,
    RiskAssesmentService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AuthModule {}
