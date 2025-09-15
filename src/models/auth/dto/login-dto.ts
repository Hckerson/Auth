import { SignUpDto } from "./signup-dto";
import { IsString, IsInt, IsBoolean, IsOptional } from "class-validator";
import { PartialType } from "@nestjs/mapped-types";

export class LoginDto extends PartialType(SignUpDto) {
  @IsBoolean()
  @IsOptional()
  rememberMe?: boolean; // Optional field for "Remember Me" functionality

  @IsOptional()
  @IsString()
  twoFactorCode?: string; // Optional field for two-factor authentication

  @IsOptional()
  @IsString()
  ipAddress?: string; // Optional field for capturing the user's IP address
}
