import bcrypt from 'bcryptjs';
import { User } from 'generated/prisma';
import { randomBytes } from 'node:crypto';
import { LoginDto } from './dto/login-dto';
import { Response, Request } from 'express';
import { Injectable } from '@nestjs/common';
import { SignUpDto } from './dto/signup-dto';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { Mailtrap } from './service/mailtrap.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { ResetPasswordDto } from './dto/reset-password-dto';

@Injectable()
export class AuthService {
  private readonly secret: string;
  private readonly encodedKey: Uint8Array;
  constructor(
    private prisma: PrismaService,
    private mailtrap: Mailtrap,
  ) {
    this.secret = process.env.COOKIE_SECRET || '';
    if (!this.secret) {
      throw new Error('Cookie secret not found');
    }
    this.encodedKey = new TextEncoder().encode(this.secret);
  }

  async login(
    loginDto: LoginDto,
    response: Response,
    threatLevel: number
  ): Promise<{ message: string; status: number }> {
    //login user and store active session in DB
    
    if (!loginDto.password)
      return { message: `Incomplete credentials`, status: 400 };
    const {
      email,
      password,
      rememberMe,
      twoFactorCode,
    } = loginDto;

    try {
      const userInfo = await this.prisma.user.findUnique({
        where: {
          email: email,
        },
      });
      if (!userInfo) return { message: `User not found`, status: 400 };
      const { password: hashedPassword, id } = userInfo;
      const isValid = await bcrypt.compare(password, hashedPassword);
      if (isValid) {
        if (rememberMe) {
          // Handle "Remember Me" functionality
          const rememberToken = randomBytes(32).toString('hex');
          response.cookie('rememberMe', rememberToken, {
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            httpOnly: true,
            sameSite: 'lax',
          });
          await this.storeSession(id, rememberToken);
        }
        
        if (threatLevel > 60){
          return { message: `Threat level too high`, status: 400 };
        }

        const sessionId = await this.storeSession(id);
        const expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
        const token = await this.encrypt({ id, expiresAt, sessionId });
        response.cookie('sessionToken', token, {
          maxAge: 2 * 24 * 60 * 60 * 1000, // 30 days
          httpOnly: true,
          sameSite: 'lax',
        });

        return { message: 'login successful', status: 200 };
      }
    } catch (error) {
      console.error(`Error finding user in db`);
    }

    return { message: 'Invalid credentials', status: 400 };
  }

  async storeSession(
    // store session in database
    userId: string,
    rememberToken: string | null = '',
  ) {
    //save session to database
    const { id } = await this.prisma.session.create({
      data: {
        userId,
        rememberToken,
      },
      select: {
        id: true,
      },
    });
    return id;
  }

  async encrypt(payload: JWTPayload) {
    // encrypt payload
    const sessionToken = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2d')
      .sign(this.encodedKey);
    return sessionToken;
  }

  async decrypt(sessionToken: string | undefined = '') {
    // decrypt payload
    const payload = await jwtVerify(sessionToken, this.encodedKey, {
      algorithms: ['HS256'],
    });
    return payload;
  }

  async signUp(signUpDto: SignUpDto) {
    // register user with email and password
    // create user in database
    const { email, password, firstName, lastName } = signUpDto;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      return this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
        },
      });
    } catch (error) {
      console.error(`Error signing up: ${error}`);
    }
  }

  async logout(response: Response) {
    response.clearCookie('rememberMe');
    response.clearCookie('sessionToken  ');
    return { message: 'Logout successful' };
  }

  async verifyEmail(email: string, verificationLink: string) {
    //send verification email
    return this.mailtrap.sendEmail({
      to: email,
      subject: 'Verify your email',
      text: 'Verify your email',
      html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; border: 1px solid #eee; padding: 24px;">
        <h2>Welcome to Tekcify!</h2>
        <p>Thank you for signing up. Please verify your email address by clicking the button below:</p>
        <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; background: #007bff; color: #fff; text-decoration: none; border-radius: 4px;">Verify Email</a>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p><a href="${verificationLink}">${verificationLink}</a></p>
        <p>If you did not request this, please ignore this email.</p>
      </div>
    `,
    });
  }

  async sendResetPasswordLink(email: string, verificationLink: string) {
    // send retset password link
    return this.mailtrap.sendEmail({
      to: email,
      subject: 'Reset your password',
      text: 'Reset your password',
      html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; border: 1px solid #eee; padding: 24px;">
        <h2>Reset your password</h2>
        <p>Click the button below to reset your password:</p>
        <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; background: #007bff; color: #fff; text-decoration: none; border-radius: 4px;">Reset Password</a>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p><a href="${verificationLink}">${verificationLink}</a></p>
        <p>If you did not request this, please ignore this email.</p>
      </div>
    `,
    });
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { email, password, token } = resetPasswordDto;

    //veify token
    try {
      const person = await this.prisma.user.findUnique({
        where: {
          email: email,
          verificationToken: token,
        },
        select: {
          verificationToken: true,
          updatedAt: true,
        },
      });

      if (!person?.verificationToken) {
        return { message: 'Token not found', status: 400 };
      }

      if (person?.verificationToken !== token) {
        return { message: 'Invalid token', status: 400 };
      }

      if (person?.updatedAt.getTime() + 3600000 < Date.now()) {
        return { message: 'Token expired', status: 400 };
      }
    } catch (error) {
      console.error(`Error fetchig user: ${error}`);
    }

    // reset password
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.prisma.user.update({
      where: {
        email: email,
      },
      data: {
        password: hashedPassword,
      },
    });
    return { message: 'Password reset successful', status: 200 };
  }

  async validateUser(profile: any): Promise<{ status: boolean; user: User }> {
    return { status: true, user: profile };
  }
}
