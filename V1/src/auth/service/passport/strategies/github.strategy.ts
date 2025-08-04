import axios from 'axios';
import { PrismaService } from 'src/prisma/prisma.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Strategy, StrategyOptions, Profile } from 'passport-github';
import { PassportStrategy, AuthModuleOptions } from '@nestjs/passport';


/**
 * Github strategy for authentication
 * 
 */
@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  public successRedirect: string;
  public failureRedirect: string;

  /**
   * 
   * @param prisma -prisma object used to communicate with database
   * @param options -Additonal options for authentication
   */
  constructor(
    private readonly prisma: PrismaService,
    private readonly options: AuthModuleOptions,

  ) {
    /**Credential required by the github passport package */
    super({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      scope: ['user:email'],
    } as StrategyOptions);
    this.successRedirect =
      this.options['successdirect'] || `/auth/successRedirect`;
    this.failureRedirect =
      this.options['failureRedirect'] || '/auth/failureRedirect';
  }

  /**
   * Fetchs user email, and validates them
   * @param accessToken -Access token issued by github to authenticate user
   * @param refreshToken -Refresh token issued by github to authenticate user
   * @param profile -profile of the user returned by github
   * @returns -Returns user details when created if not found
   * @throws unathorized exception if user is not found
   */
  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    const { provider, displayName } = profile;
    const userDetail = await axios.get('https://api.github.com/user/emails', {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${accessToken}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    const primary = userDetail.data.find(
      (e: { primary: boolean }) => e.primary === true,
    );
    const { email, verified } = primary;
      this.successRedirect = this.options['successdirect'] || `/auth/successRedirect/${email}`;
    const user = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });
    if (!user || user == null || user == undefined) {
      return await this.prisma.user.create({
        data: {
          email: email.toLowerCase(),
          emailVerified: verified,
          password: 'github',
          username: displayName,
          provider: provider,
        },
      });

    } else if (user) {
      const { provider, email } = user;
      if (provider !== 'github')
        throw new UnauthorizedException(
          `User with email ${email} already exists with ${provider} provider`,
        );
      else return user;
    } else {
      throw new UnauthorizedException('An error occured');
    }
  }
}
