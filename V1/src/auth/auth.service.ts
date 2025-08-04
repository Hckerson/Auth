import * as bcrypt from 'bcryptjs';
import { createHash } from 'crypto';
import * as geoip from 'geoip-lite';
import { Lookup } from 'geoip-lite';
import { randomBytes } from 'node:crypto';
import { LoginDto } from './dto/login-dto';
import { Request, Response } from 'express';
import { Injectable } from '@nestjs/common';
import { SignUpDto } from './dto/signup-dto';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { Mailtrap } from './service/mailtrap.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { RiskAssesmentService } from 'src/lib/risk-assesment.service';

type ValidateUserSuccess = {
  success: true;
  data: {
    isValid: boolean;
    id: string;
  };
};

type ValidateUserError = {
  success: false;
  error: {
    message: string;
    status: number;
  };
};

type validateUserResult = ValidateUserSuccess | ValidateUserError;

@Injectable()
export class AuthService {
  /**
   * Service responsible for all authentication logic
   *        -login, logout
   *        -signup, session creation and deletion,
   *        -reset password
   *        -encryption and decryption of session
   */

  // secret used to encrypt and decrypt session
  private readonly secret: string;
  // encodec version of the secret
  private readonly encodedKey: Uint8Array;

  /**
   * @param mailtrap -Service for sending emails and verification link
   * @param prisma -Service for interacting with database
   * @param risk -Risk assessment service for evaluating login threat level
   * @throws {Error} if cookie secret is not found
   */
  constructor(
    private mailtrap: Mailtrap,
    private prisma: PrismaService,
    private risk: RiskAssesmentService,
  ) {
    this.secret = process.env.COOKIE_SECRET || '';
    if (!this.secret) {
      throw new Error('Cookie secret not found');
    }
    this.encodedKey = new TextEncoder().encode(this.secret);
  }

  /**
   * Authenticates a user, creates session and stores secret
   * @param loginDto -Data object transfer containing password, email etc
   * @param response -Express response(to set token)
   * @param threatLevel -Threat level to determine if login would be made
   * @returns -Resoves an object with a message and an HTTP status code
   */
  async login(
    loginDto: LoginDto,
    response: Response,
    threatLevel: number,
  ): Promise<{ message: string; status: number }> {
    if (!loginDto.password)
      return { message: `Incomplete credentials`, status: 400 };
    const { email = '', password, rememberMe, twoFactorCode } = loginDto;

    try {
      const result = await this.validateUser(email, password);
      if (!result.success) return result.error;
      const { isValid, id } = result.data;
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

        if (threatLevel > 55) {
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
        this.risk.threatLevel = 0;
        return { message: 'login successful', status: 200 };
      }
      return { message: 'Invalid credentials', status: 400 };
    } catch (error) {
      console.error(`Error finding user in db`);
    }
    return { message: 'error logging in user', status: 400 };
  }

  /**
   * validate user credentials without creating a session
   * @param email - User email address
   * @param password -User password
   * @returns true if valid else false, return an object if not user is found
   */
  async validateUser(
    email: string,
    password: string,
  ): Promise<validateUserResult> {
    const userInfo = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });

    if (!userInfo)
      return {
        success: false,
        error: { message: 'User not found', status: 400 },
      };
    const { password: hashedPassword, id } = userInfo;
    const isValid = await bcrypt.compare(password, hashedPassword);
    return { success: true, data: { isValid, id } };
  }

  /**
   *
   * @param userId -Id of the authenticated user
   * @param [rememberToken] -Optional remember token
   * @returns -id of the just created session
   */
  async storeSession(userId: string, rememberToken: string | null = '') {
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

  /**
   * Sign and encrypt a new jwt payload
   * @param payload -The jwt payload (contains user id and expiration date, etc)
   * @returns -The signed and encrypted jwt
   */
  async encrypt(payload: JWTPayload) {
    const sessionToken = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2d')
      .sign(this.encodedKey);
    return sessionToken;
  }

  /**
   * Decrypt and verify a jwt
   * @param sessionToken -User session token
   * @returns -Returns the decrypted payload
   */
  async decrypt(sessionToken: string | undefined = '') {
    // decrypt payload
    const payload = await jwtVerify(sessionToken, this.encodedKey, {
      algorithms: ['HS256'],
    });
    return payload;
  }

  /**
   *
   * @param signUpDto Data transfer object containing email and password
   * @param ipAddress -User ip address for ip geolocation
   * @param request -Express request object to extract header
   * @returns
   */
  async signUp(signUpDto: SignUpDto, ipAddress: string, request: Request) {
    const { email, password } = signUpDto;
    ipAddress = '146.70.99.210';
    //check if user Exists
    const user = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });

    if (user) return `User already exists`;

    const geo = geoip.lookup(ipAddress);
    if (geo === null) return 'Error getting geo data';
    const { region, country, timezone, city }: Lookup = geo;

    const userAgent = request.headers['user-agent'] || '';
    const acceptLanguage = request.headers['accept-language'] || '';
    const fingerPrint = `${userAgent}-${acceptLanguage}-${ipAddress}`;
    const hash = createHash('sha256').update(fingerPrint).digest('hex');

    // create user in database
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      try {
        return this.prisma.user.create({
          data: {
            email: email.toLowerCase(),
            password: hashedPassword,
            provider: 'local',
            username: email.split('@')[0],
            lastLoginIp: ipAddress,
            lastKnownDevice: hash,
            geoData: {
              create: {
                region,
                country,
                timezone,
                city,
              },
            },
          },
          include: {
            geoData: true,
          },
        });
      } catch (error) {
        console.error(`Error creating user in db: ${error}`);
      }
    } catch (error) {
      console.error(`Error signing up: ${error}`);
    }
  }

  /**
   * Clear user session to logout user
   * @param response -Express response object to clear cookie
   * @returns -Returns a success message
   */
  async logout(response: Response) {
    response.clearCookie('rememberMe');
    response.clearCookie('sessionToken');
    return { message: 'Logout successful' };
  }

  /**
   * Sending verification email to the user
   * @param email -Email address of the user
   * @param verificationLink -Verification link to be sent
   * @returns Object containing message and status of the response
   */
  async sendVerificationEmail(email: string, verificationLink: string) {
    //send verification email
    const response = await this.mailtrap.sendEmail({
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
    if (!response?.success)
      return { message: 'Error sending email', status: 500 };
    return { message: 'Email sent', status: 200 };
  }

  /**
   *Verify user email using token
   * @param email -Email address of the user
   * @param token -Verification token stored earlier on during sign up
   * @returns -Object containg message and status
   */
  async verifyEmail(email: string, token: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
        verificationToken: token,
      },
      select: {
        verificationToken: true,
      },
    });
    if (!user?.verificationToken)
      return { message: 'Token not found', status: 400 };
    const isValid = user.verificationToken == token;
    if (!isValid) return { message: 'Invalid token', status: 400 };
    // verify email
    await this.prisma.user.update({
      where: {
        email: email.toLowerCase(),
        verificationToken: token,
      },
      data: {
        verificationToken: null,
        emailVerified: true,
      },
    });
    return { message: 'Email verified', status: 200 };
  }
  /**
   * Send verification link to reset password
   * @param email -Email of the user
   * @param verificationLink -Link to be sent
   * @returns Object containing message and status
   */
  async sendResetPasswordLink(email: string, verificationLink: string) {
    // send retset password link
    console.log(`Sending password reset link for ${email}`);
    const response = await this.mailtrap.sendEmail({
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
    if (!response?.success)
      return { message: 'Error sending email', status: 500 };
    return { message: 'Email sent', status: 200 };
  }

  async success(response: Response, email: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
      select: { id: true },
    });
    if (!user) {
      return { message: 'User not found', status: 400 };
    }
    const id = user.id;
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

  /**
   * Reset user password after validating token
   * @param resetPasswordDto -Data transfer object containing email, password and token
   * @returns -Object containing message and status
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { email, password, token } = resetPasswordDto;

    //veify token
    try {
      const person = await this.prisma.user.findUnique({
        where: {
          email: email.toLowerCase(),
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

      if (person?.updatedAt.getTime() + 300000 < Date.now()) {
        return { message: 'Token expired', status: 400 };
      }
    } catch (error) {
      console.error(`Error fetchig user: ${error}`);
    }

    // reset password
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.prisma.user.update({
      where: {
        email: email.toLowerCase(),
      },
      data: {
        password: hashedPassword,
      },
    });
    return { message: 'Password reset successful', status: 200 };
  }
}
