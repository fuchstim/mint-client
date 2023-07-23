import axios, { AxiosInstance } from 'axios';
import Logger from '@ftim/logger';
const logger = Logger.ns('MobileMint');

import type { AuthClient } from '../auth-client';
import { BASE_URL, defaultHeaders } from './_constants';
import { CookieStore } from '../common/cookie-store';
import { TGetNewUuidResponse, TRegisterDeviceIdResponse } from './_types';

export class MobileMintClient {
  private authClient: AuthClient;
  private client: AxiosInstance;
  private cookieStore: CookieStore = new CookieStore();

  constructor(authClient: AuthClient) {
    this.authClient = authClient;

    this.client = axios.create({
      baseURL: BASE_URL,
      headers: {
        ...defaultHeaders,
      },
    });

    this.client.interceptors.request.use(this.cookieStore.requestInterceptor);
    this.client.interceptors.response.use(this.cookieStore.responseInterceptor);
  }

  private set userId(userId: string) {
    this.client.defaults.headers['mint-userid'] = userId;
  }

  private get userId(): string | undefined {
    return this.client.defaults.headers['mint-userid'] as string | undefined;
  }

  async init() {
    logger.info('Initializing...');

    await this.initCookieStore();

    const deviceId = await this.getDeviceId();

    this.client.interceptors.request.use(async request => {
      const accessToken = await this.authClient.getAccessToken();

      request.headers.set('Authorization', `Bearer ${accessToken}`);

      return request;
    });

    this.userId = await this.registerDeviceId(deviceId);

    await this.submitDeviceToken(deviceId, this.userId);
  }

  private async initCookieStore() {
    logger.info('Initializing cookie store...');

    this.cookieStore.reset();

    await this.client.post('testing.xevent');

    await this.client.post(
      'getUserPod.xevent',
      new URLSearchParams({
        username: this.authClient.getUsername(),
        clientType: 'Mint',
      }).toString()
    );

    logger.info('Initialized cookie store.');
  }

  private async getDeviceId() {
    logger.info('Retrieving new device id...');

    const { data, } = await this.client.post<TGetNewUuidResponse>('getNewUuid.xevent');

    logger.info(`Retrieved device id: ${data.uuid}`);

    return data.uuid;
  }

  private async registerDeviceId(deviceId: string) {
    logger.info(`Regisering device id ${deviceId}...`);

    const params = {
      MMQP_platform: 'iPhone',
      MMQP_protocol: '150.70.0',
      MMQP_version: '150.70.0',
      MMQP_request: 'registerUser',
    };

    const payload = {
      deviceUniq: deviceId,

      deviceModelID: 'iPhone15,2',
      version: '150.70.0',
      protocol: '150.70.0',
      clientType: 'Mint',
      deviceSysVersion: '16.5.1',
      deviceModel: 'iPhone',
      deviceName: 'iPhone',
      platform: 'iphone',
      demo: 'false',
      buildNumber: '1.24203',
      deviceSysName: 'iOS',
      deviceLocalModel: 'iPhone',
    };

    const { data, } = await this.client.post<TRegisterDeviceIdResponse>(
      'mobileLogin.xevent',
      new URLSearchParams(payload).toString(),
      { params, }
    );

    logger.info(`Registered device ${deviceId}. Retrieved user id ${data.userId}`);

    return String(data.userId);
  }

  private async submitDeviceToken(deviceId: string, userId: string) {
    const params = {
      MMQP_platform: 'iPhone',
      MMQP_protocol: '150.70.0',
      MMQP_version: '150.70.0',
      MMQP_request: 'submitToken',
    };

    const payload = {
      deviceUniq: deviceId,
      deviceToken: userId,

      deviceModelID: 'iPhone15,2',
      version: '150.70.0',
      protocol: '150.70.0',
      clientType: 'Mint',
      deviceSysVersion: '16.5.1',
      deviceModel: 'iPhone',
      deviceName: 'iPhone',
      platform: 'iphone',
      demo: 'false',
      buildNumber: '1.24203',
      deviceSysName: 'iOS',
      deviceLocalModel: 'iPhone',
    };

    await this.client.post(
      'mobileSubmitDeviceToken.xevent',
      new URLSearchParams(payload).toString(),
      { params, }
    );
  }
}
