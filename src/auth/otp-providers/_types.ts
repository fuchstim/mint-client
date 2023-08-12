/**
 * Implement a custom OTP provider by implementing this interface
 */
export interface IOTPProvider {
  getCode(): string | Promise<string>;
}
