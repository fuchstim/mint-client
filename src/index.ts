import SessionStore from './common/session-store';
import AuthClient from './auth';
import MobileMintClient, { TTransaction, TUserDataResponse } from './mobile-mint-client';
import DataApiClient from './data-api-client';
import { TMFAInputProvider } from './auth/access-platform-client';
import requestCaptchaToken from './auth/captcha-server';
import { TCategory } from './mobile-mint-client/_types';

export { SessionStore, requestCaptchaToken };

export type { TUserDataResponse, TTransaction, ECategoryType, TCategory } from './mobile-mint-client';
export type { EMFAInputType } from './auth/access-platform-client';

export type TMintClientOptions = {
  username: string,
  password: string,
  mfaInputProvider: TMFAInputProvider
  sessionStore?: SessionStore
};

export default class MintClient {
  private sessionStore: SessionStore;
  private authClient: AuthClient;
  private mobileMintClient: MobileMintClient;
  private dataApiClient: DataApiClient;

  constructor(options: TMintClientOptions) {
    const { username, password, mfaInputProvider, sessionStore, } = options;

    this.sessionStore = sessionStore || new SessionStore({
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
