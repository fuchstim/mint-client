import totpGenerator from 'totp-generator';
import Logger from '@ftim/logger';
const logger = Logger.ns('MFAHelpers', 'TOTP');

export function getTOTPToken(secret: string): Promise<string> {
  logger.info('Generating TOTP token...');

  try {
    const token = totpGenerator(secret);

    logger.info('TOTP token generated');

    return Promise.resolve(token);
  } catch (e) {
    const error = e as Error;

    logger.error('Failed to generate TOTP token:', error.message);

    throw e;
  }
}
