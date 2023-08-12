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

export { EOTPType } from './auth/access-platform-client';

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

  async getUserProfile(...params: Parameters<MobileMintClient['getUserProfile']>): ReturnType<MobileMintClient['getUserProfile']> {
    const userProfile = await this.mobileMintClient.getUserProfile();

    return userProfile;
  }

  async getCategories(...params: Parameters<MobileMintClient['getCategories']>): ReturnType<MobileMintClient['getCategories']> {
    const categories = await this.mobileMintClient.getCategories();

    return categories;
  }

  async getTransactions(...params: Parameters<MobileMintClient['getTransactions']>): ReturnType<MobileMintClient['getTransactions']> {
    const transactions = await this.mobileMintClient.getTransactions(...params);

    return transactions;
  }

  async getNetworth(...params: Parameters<MobileMintClient['getNetworth']>): ReturnType<MobileMintClient['getNetworth']> {
    const networth = await this.mobileMintClient.getNetworth(...params);

    return networth;
  }

  async getBudgetSummary(...params: Parameters<DataApiClient['getBudgetSummary']>): ReturnType<DataApiClient['getBudgetSummary']> {
    const budgetSummary = await this.dataApiClient.getBudgetSummary(...params);

    return budgetSummary;
  }

  async getOverviewChart(...params: Parameters<DataApiClient['getOverviewChart']>): ReturnType<DataApiClient['getOverviewChart']> {
    const overviewChart = await this.dataApiClient.getOverviewChart(...params);

    return overviewChart;
  }
}
