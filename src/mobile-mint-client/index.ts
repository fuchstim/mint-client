import axios, { AxiosInstance } from 'axios';

import Logger from '@ftim/logger';
const logger = Logger.ns('MobileMint');

import { CookieStore } from '../common/cookie-store';
import { SessionStore } from '../common/session-store';
import { Lock } from '../common/lock';
import dayjs from '../common/dayjs';

import type { AuthClient } from '../auth-client';
import { BASE_URL, defaultHeaders } from './_constants';
import { TGetNewUuidResponse, TProcessRequestTypes, TRegisterDeviceIdResponse } from './_types';

export type TMobileMintClientOptions = {
  sessionStore: SessionStore,
  authClient: AuthClient,
};

const MOBILE_MINT_CLIENT_LOCK = new Lock('mobile-mint-client');

export class MobileMintClient {
  private sessionStore: SessionStore;
  private authClient: AuthClient;
  private client: AxiosInstance;
  private cookieStore: CookieStore = new CookieStore();

  private userId?: string;
  private deviceId?: string;

  constructor({ sessionStore, authClient, }: TMobileMintClientOptions) {
    this.sessionStore = sessionStore;
    this.authClient = authClient;

    this.client = axios.create({
      baseURL: BASE_URL,
      headers: {
        ...defaultHeaders,
      },
    });

    this.client.interceptors.request.use(this.cookieStore.requestInterceptor);
    this.client.interceptors.response.use(this.cookieStore.responseInterceptor);

    this.client.interceptors.request.use(async request => {
      if (!this.userId) { return request; }

      const accessToken = await this.authClient.getAccessToken();

      request.headers.set('Authorization', `Bearer ${accessToken}`);
      request.headers.set('mint-userid', this.userId);

      return request;
    });

    const initInterceptor = this.client.interceptors.request.use(async request => {
      this.client.interceptors.request.eject(initInterceptor);

      await MOBILE_MINT_CLIENT_LOCK.runWithLock(async () => {
        if (this.userId) { return; }

        await this.init();
      });

      return request;
    });
  }

  async getUserProfile() {

  }

  async getCategories() {
    const categories = await this.processRequest(
      'getCategories',
      'categoriesResponse',
      { includeDeletedCategories: true, modifiedFrom: '0', }
    );

    return categories.entries;
  }

  private async init(bypassSessionStore = false) {
    logger.info('Initializing...');

    if (!bypassSessionStore) {
      const hydrationSuccessful = this.hydrateFromSessionStore();
      if (hydrationSuccessful) {
        logger.info('Initialized from session store.');

        return;
      }
    }

    await this.initCookieStore();

    this.deviceId = await this.getDeviceId();

    this.userId = await this.registerDeviceId(this.deviceId);

    await this.submitDeviceToken(this.deviceId, this.userId);

    this.sessionStore.set('mobileMint', {
      deviceId: this.deviceId,
      userId: this.userId,
      cookies: this.cookieStore.bulkGet(),
    });
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

      buildNumber: '1.24203',
      clientType: 'Mint',
      demo: 'false',
      deviceLocalModel: 'iPhone',
      deviceModel: 'iPhone',
      deviceModelID: 'iPhone15,2',
      deviceName: 'iPhone',
      deviceSysName: 'iOS',
      deviceSysVersion: '16.5.1',
      platform: 'iphone',
      protocol: '150.70.0',
      version: '150.70.0',
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

      buildNumber: '1.24203',
      clientType: 'Mint',
      demo: 'false',
      deviceLocalModel: 'iPhone',
      deviceModel: 'iPhone',
      deviceModelID: 'iPhone15,2',
      deviceName: 'iPhone',
      deviceSysName: 'iOS',
      deviceSysVersion: '16.5.1',
      platform: 'iphone',
      protocol: '150.70.0',
      version: '150.70.0',
    };

    await this.client.post(
      'mobileSubmitDeviceToken.xevent',
      new URLSearchParams(payload).toString(),
      { params, }
    );
  }

  private hydrateFromSessionStore() {
    const store = this.sessionStore.get('mobileMint');
    if (!store) { return false; }

    const { deviceId, userId, cookies, } = store;

    if (!deviceId || !userId || !cookies) {
      logger.warn('Invalid session store data.');

      return false;
    }

    this.cookieStore.reset();
    this.cookieStore.bulkSet(cookies);
    this.userId = userId;
    this.deviceId = deviceId;

    return true;
  }

  private async processRequest<T extends keyof TProcessRequestTypes>(
    requestType: T,
    responseKey: TProcessRequestTypes[T]['responseKey'],
    payload?: TProcessRequestTypes[T]['payload']
  ): Promise<TProcessRequestTypes[T]['response']> {
    const params = {
      clientID: this.deviceId,

      apiProtocol: '150.70.0',
      buildNumber: '1.24203',
      clientType: 'Mint',
      clientVersion: '150.70.0',
      deviceModel: 'iPhone',
      deviceName: 'iPhone',
      platform: 'iPhone',
      systemName: 'iOS',
      systemVersion: '16.5.1',
    };

    const { data, } = await this.client.post(
      'processRequest.xevent',
      {
        [requestType]: {
          requestID: `${requestType} request ${dayjs().format('YYYY-MM-DD, H:mm:ss A z')}`,
          ...payload,
        },
      },
      { params, }
    );

    return data[responseKey] as TProcessRequestTypes[T]['response'];
  }
}
