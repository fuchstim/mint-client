import axios, { AxiosInstance } from 'axios';

import type { AuthClient } from '../auth-client';

export class MobileMintClient {
  private client: AxiosInstance;

  constructor(authClient: AuthClient) {
    this.client = axios.create({
      baseURL: 'https://mobile.mint.com',
      headers: {

      },
    });
  }
}
