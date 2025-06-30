import { SignUpDto } from "./signup-dto";
import { PartialType } from "@nestjs/mapped-types";


export class LoginDto extends PartialType(SignUpDto) {
  rememberMe?: boolean; // Optional field for "Remember Me" functionality
  twoFactorCode?: string; // Optional field for two-factor authentication 
  deviceInfo?: {
    deviceType: string; // e.g., 'mobile', 'desktop'
    deviceId: string; // Unique identifier for the device
  }; // Optional field for device information
  ipAddress?: string; // Optional field for capturing the user's IP address
  userAgent?: string; // Optional field for capturing the user's browser/user agent
  locale?: string; // Optional field for capturing the user's preferred language/locale
  sessionId?: string; // Optional field for tracking the session ID
  redirectUrl?: string; // Optional field for redirecting after login
}