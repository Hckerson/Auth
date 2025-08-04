import { SignUpDto } from "./signup-dto";
import { PartialType } from "@nestjs/mapped-types";


export class LoginDto extends PartialType(SignUpDto) {
  rememberMe?: boolean; // Optional field for "Remember Me" functionality
  twoFactorCode?: string; // Optional field for two-factor authentication 
  ipAddress?: string; // Optional field for capturing the user's IP address
}