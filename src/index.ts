import Logger from '@ftim/logger';
Logger.setPrefix('MintClient');

import EncryptedFileSessionStore, { ISessionStore } from './common/session-store';
import AuthClient from './auth';
import MobileMintClient from './mobile-mint-client';
import DataApiClient from './data-api-client';
import { TOTPProviders } from './auth/access-platform-client';

export { default as EncryptedFileSessionStore } from './common/session-store';
export type { ISessionStore } from './common/session-store';

export * as OTPProviders from './auth/otp-providers';

export { EOTPType, TOTPProviders } from './auth/access-platform-client';

export { ECategoryType } from './mobile-mint-client';
export type { TUserDataResponse, TTransaction, TCategory, TNetworthResponse } from './mobile-mint-client';

/**
 * Mint client options
 */
export type TMintClientOptions = {
  /** The username or email used to sign into your Intuit account */
  username: string,
  /** The password used to sign into your Intuit account */
  password: string,
  /** A list of providers that will return a one-time-password when requested during the initial sign-in process. Read more {@link EOTPType | here} about the different OTP token types. */
  otpProviders: TOTPProviders
  /** A class implementing {@link ISessionStore}. Effectively a key-value store to persist and retrieve various information related to the current authentication session (e.g. authorization and refresh tokens). Defaults to {@link EncryptedFileSessionStore} using the above username & password as credentials. */
  sessionStore?: ISessionStore
};

/**
 * @example
 * ```typescript
 * import MintClient, { EOTPType, OTPProviders } from '@ftim/mint-client';
 *
 * const client = new MintClient({
 *   username: 'supersaver',
 *   password: 'supersecurepassword',
 *   otpProviders: {
 *     [EOTPType.CAPTCHA_TOKEN]: new OTPProviders.CaptchaOTPProvider(),
 *     [EOTPType.TOTP]: new OTPProviders.TOTPProvider('TOTPSECRET'),
 *     [EOTPType.EMAIL_OTP]: new OTPProviders.EmailOTPProvider({
 *       host: 'imap.gmail.com',
 *       port: 993,
 *       auth: {
 *         user: 'supersaver@gmail.com',
 *         pass: 'supersecurepassword',
 *       },
 *     }),
 *   },
 * });
 * ```
 */
export default class MintClient {
  private sessionStore: ISessionStore;
  private authClient: AuthClient;
  private mobileMintClient: MobileMintClient;
  private dataApiClient: DataApiClient;

  constructor(options: TMintClientOptions) {
    const { username, password, otpProviders, sessionStore, } = options;

    this.sessionStore = sessionStore ?? new EncryptedFileSessionStore({
      identifier: username,
      secret: password,
    });

    this.authClient = new AuthClient({
      sessionStore: this.sessionStore,
      username,
      password,
      otpProviders,
    });

    this.mobileMintClient = new MobileMintClient({
      sessionStore: this.sessionStore,
      authClient: this.authClient,
    });

    this.dataApiClient = new DataApiClient(this.authClient);
  }

  async getUserProfile(): ReturnType<MobileMintClient['getUserProfile']> {
    const userProfile = await this.mobileMintClient.getUserProfile();

    return userProfile;
  }

  async getCategories(options: Parameters<MobileMintClient['getCategories']>[0]): ReturnType<MobileMintClient['getCategories']> {
    const categories = await this.mobileMintClient.getCategories(options);

    return categories;
  }

  async getTransactions(options: Parameters<MobileMintClient['getTransactions']>[0]): ReturnType<MobileMintClient['getTransactions']> {
    const transactions = await this.mobileMintClient.getTransactions(options);

    return transactions;
  }

  async getNetworth(options: Parameters<MobileMintClient['getNetworth']>[0]): ReturnType<MobileMintClient['getNetworth']> {
    const networth = await this.mobileMintClient.getNetworth(options);

    return networth;
  }

  async getBudgetSummary(options: Parameters<DataApiClient['getBudgetSummary']>[0]): ReturnType<DataApiClient['getBudgetSummary']> {
    const budgetSummary = await this.dataApiClient.getBudgetSummary(options);

    return budgetSummary;
  }

  async getOverviewChart(options: Parameters<DataApiClient['getOverviewChart']>[0]): ReturnType<DataApiClient['getOverviewChart']> {
    const overviewChart = await this.dataApiClient.getOverviewChart(options);

    return overviewChart;
  }
}
