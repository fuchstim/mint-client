import prompts from 'prompts';

import Logger from '../../common/logger';
const logger = Logger.ns('OTPProvider', 'UserInput');

import { IOTPProvider } from './_types';

/**
 * Prompts the user to input an OTP token
 *
 * @example
 * ```typescript
 * new UserInputOTPProvider('Please enter your OTP token:');
 * ```
*/

export class UserInputOTPProvider implements IOTPProvider {
  private prompt: string;

  constructor(prompt: string) {
    this.prompt = prompt;
  }

  public async getCode(): Promise<string> {
    logger.info('Prompting user for OTP token...');

    const { code, } = await prompts([
      {
        type: 'text',
        name: 'code',
        message: this.prompt,
      },
    ]);

    logger.info(`User entered OTP token: ${code}`);

    return code;
  }
}
