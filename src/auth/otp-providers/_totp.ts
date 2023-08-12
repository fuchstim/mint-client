import totpGenerator from 'totp-generator';
import Logger from '@ftim/logger';
import { IOTPProvider } from './_types';
const logger = Logger.ns('OTPProvider', 'TOTP');

/**
 * Generates a TOTP token using the provided secret
 *
 * @example
 * ```typescript
 * new TOTPProvider('TOTPSECRET');
 * ```
*/

export class TOTPProvider implements IOTPProvider {
  private secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  public getCode(): string {
    logger.info('Generating TOTP token...');

    try {
      const token = totpGenerator(this.secret);

      logger.info('TOTP token generated');

      return token;
    } catch (e) {
      const error = e as Error;

      logger.error('Failed to generate TOTP token:', error.message);

      throw e;
    }
  }
}
