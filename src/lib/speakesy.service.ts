import * as speakeasy from 'speakeasy';
import { Injectable } from '@nestjs/common';
import { QrcodeService } from './qr-code.service';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class SpeakeasyService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly qrcodeService: QrcodeService,
  ) {}

  /**
   * Creates and stores a new TOTP secret for the given user,
   * returns the otpauth URL for QR code generation.
   */
  async setupTwoFactor(userId: string): Promise<string> {
    const secret = speakeasy.generateSecret();
    // Store the base32 secret in the user record
    await this.prisma.user.update({
      where: { id: userId },
      data: { speakeasySecret: secret.base32 },
    });
    // Return the URL for the authenticator app
    return secret.otpauth_url!;
  }

  /**
   * Generates a QR code image (data URL) for the otpauth URL.
   */
  async getQrCodeForUser(userId: string): Promise<string | undefined> {
    // Retrieve the stored secret
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { speakeasySecret: true },
    });
    if (!user?.speakeasySecret) {
      throw new Error('2FA not set up for this user');
    }
    const otpauthUrl = speakeasy.otpauthURL({
      secret: user.speakeasySecret,
      label: `MyApp (${userId})`,
      encoding: 'base32',
    });
    return this.qrcodeService.generateQrCode(otpauthUrl);
  }

  /**
   * Verifies a TOTP token provided by the user.
   */
  async verifyToken(userId: string, token: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { speakeasySecret: true },
    });
    if (!user?.speakeasySecret) {
      throw new Error('2FA not set up for this user');
    }
    return speakeasy.totp.verify({
      secret: user.speakeasySecret,
      encoding: 'base32',
      token,
      window: 2, // allow one-step clock drift
    });
  }

  async update2faStatus(userId: string) {
    const user = await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        twofaVerified: true,
      },
    });
  }
}
