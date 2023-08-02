import EncryptedFileSessionStore, { ISessionStore } from './common/session-store';
import AuthClient from './auth';
import MobileMintClient, { TTransaction, TUserDataResponse } from './mobile-mint-client';
import DataApiClient from './data-api-client';
import { TMFAInputProvider } from './auth/access-platform-client';
import { TCategory } from './mobile-mint-client/_types';

export { default as EncryptedFileSessionStore } from './common/session-store';
export { default as requestCaptchaToken } from './auth/captcha-server';

export { ECategoryType } from './mobile-mint-client';
export { EMFAInputType } from './auth/access-platform-client';
export type { TUserDataResponse, TTransaction, TCategory } from './mobile-mint-client';
export type { ISessionStore } from './common/session-store';
export type { TCaptchaServerOptions } from './auth/captcha-server';

export type TMintClientOptions = {
  username: string,
  password: string,
  mfaInputProvider: TMFAInputProvider
  sessionStore?: ISessionStore
};

export default class MintClient {
  private sessionStore: ISessionStore;
  private authClient: AuthClient;
  private mobileMintClient: MobileMintClient;
  private dataApiClient: DataApiClient;

  constructor(options: TMintClientOptions) {
    const { username, password, mfaInputProvider, sessionStore, } = options;

    this.sessionStore = sessionStore ?? new EncryptedFileSessionStore({
      identifier: username,
      secret: password,
    });

    this.authClient = new AuthClient({
      sessionStore: this.sessionStore,
      username,
      password,
      mfaInputProvider,
    });

    this.mobileMintClient = new MobileMintClient({
      sessionStore: this.sessionStore,
      authClient: this.authClient,
    });

    this.dataApiClient = new DataApiClient(this.authClient);
  }

  async getUserProfile(): Promise<TUserDataResponse> {
    const userProfile = await this.mobileMintClient.getUserProfile();

    return userProfile;
  }

  async getCategories(): Promise<TCategory[]> {
    const categories = await this.mobileMintClient.getCategories();

    return categories.entries;
  }

  async getTransactions(accountIds: number[], fromDate: Date, toDate: Date, limit: number): Promise<TTransaction[]> {
    const transactions = await this.mobileMintClient.getTransactions(accountIds, fromDate, toDate, limit);

    return transactions;
  }

}
