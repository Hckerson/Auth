import { genToken } from './gen-token';
import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class VerificationLink {
  private token: string;
  constructor(private readonly prisma: PrismaService) {}

  async generateVerificationLink(email: string) {
    // generate verification link and store in database
    this.token = genToken();
    await this.storeVerificatoinLink(email);
    return `https://authTekcify.vercel.app/verify?email=${email}&token=${this.token}`;
  }

  async storeVerificatoinLink(email: string) {
    // function to store verification token in database
    const user = await this.prisma.user.update({
      where: {
        email: email,
      },
      data: {
        verificationToken: this.token,
      },
    });
  }
}
