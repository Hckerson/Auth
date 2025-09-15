import { randomBytes } from "node:crypto";

export function randomToken () {
  return randomBytes(32).toString('hex');
}