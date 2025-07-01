import * as speakeasy from 'speakeasy';
import { OnModuleInit } from '@nestjs/common';
import { QrcodeService } from './qr-code.service';
import { PrismaService } from 'src/prisma/prisma.service';

export class SpeakesayService implements OnModuleInit {
  constructor(
    private userId: string,
    private secret: {
      ascii: string;
      base32: string;
      otpauth_url?: string;
      hex: string;
    },
    private readonly prisma: PrismaService,
    private readonly qrcodeService: QrcodeService,
  ) {}
  async onModuleInit() {
    this.secret = speakeasy.generateSecret();
    await this.prisma.user.update({
      where: {
        id: this.userId,
      },
      data: {
        speakeasySecret: this.secret.base32,
      },
    });
  }

  async generateToken() {
    const token = speakeasy.totp({
      secret: this.secret.base32,
      encoding: 'base32',
    });
  }

  async getQrCode() {
    if (this.secret.otpauth_url)
      return this.qrcodeService.generateQrCode(this.secret.otpauth_url);
  }

  async verifyToken(token: string, id: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          id,
        },
        select: {
          speakeasySecret: true,
        },
      });
      if (!user?.speakeasySecret) return `Speakeasy secret not found`;
      const { speakeasySecret } = user;
      return speakeasy.totp.verify({
        secret: speakeasySecret,
        encoding: 'base32',
        token,
        window: 6
      });
    } catch (error) {
      console.error(`Error finding speakeasy secret: ${error}`);
    }
  }
}
