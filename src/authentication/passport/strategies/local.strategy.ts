import { Strategy } from 'passport-local';
import { AuthService } from 'src/models/auth/auth.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy, AuthModuleOptions } from '@nestjs/passport';

@Injectable()
/**
 * LocalStrategy is a passport strategy that is used to authenticate a user with a username and password.
 * @see https://docs.nestjs.com/security/authentication
 *
 */
export class LocalStrategy extends PassportStrategy(Strategy) {
  /**
   * Constructs a new instance of local strategy
   * @param authService -Service for authenticating users
   * @param options - Additional configuration option for the auth module
   */
  constructor(
    private readonly authService: AuthService,
    private readonly options: AuthModuleOptions,
  ) {
    /**Configures passport to use email instead of the default username field */
    super({ usernameField: 'email' });
  }

  /**
   * Validates user using username and password and returns user data
   * @param username -User username
   * @param password -User pasword
   * @returns  -returns user data if authentication is successful
   * @throws unathorized exception if user is not found
   */
  async validate(username: string, password: string) {
    const result = await this.authService.validateUser(username, password);

    // check if there is a data key in the returned payload
    if (result?.data == undefined) {
      if (result?.message == 'Invalid credentials') {
        throw new UnauthorizedException('Invalid credentials');
      }
    }
    
    return result?.data;
  }
}
