import { randomBytes } from "node:crypto";

export function genToken() {
  return randomBytes(32).toString('hex');
}