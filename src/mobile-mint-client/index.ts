import axios, { AxiosInstance } from 'axios';

import Logger from '@ftim/logger';
const logger = Logger.ns('MobileMint');

import { CookieStore } from '../common/cookie-store';
import { SessionStore } from '../common/session-store';
import { Lock } from '../common/lock';
import dayjs from '../common/dayjs';

import type { AuthClient } from '../auth-client';
import { BASE_URL, defaultHeaders, defaultMQPPRequestParams, defaultMQPPRequestPayload } from './_constants';
import { TGetNewUuidResponse, TMMQPBundledRequestTypes, TMMQPRequestTypes, TProcessRequestTypes } from './_types';

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
    const userProfile = await this.processMMQPRequest(
      'UserData_primary',
      'mobileData.xevent',
      {
        deviceUniq: this.deviceId!,
        countAsLogin: false,
        isManualTransactionsRequest: true,
        getBudgets: false,
        dataType: 'primary',
        allBudgets: true,
      }
    );

    return userProfile;
  }

  async getCategories() {
    const categories = await this.processRequest(
      'getCategories',
      'categoriesResponse',
      { includeDeletedCategories: true, modifiedFrom: '0', }
    );

    return categories;
  }

  async getTransactions() {
    const transactions = await this.processBundledMMQPRequest(
      'fetchModifiedTransactions',
      'getModifiedTransactions',
      'MintUserMobileService',
      {
        visibleDateFrom: 1688626800000,
        visibleDateTo: 1689984000000,
        accountIDs: [ 2460887, 2460886, 2460888, ],
        maxCount: 100,
      }
    );

    return transactions;
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
    logger.info(`Registering device id ${deviceId}...`);

    const { userId, } = await this.processMMQPRequest(
      'registerUser',
      'mobileLogin.xevent',
      { deviceUniq: deviceId, }
    );

    logger.info(`Registered device ${deviceId}. Retrieved user id ${userId}`);

    return String(userId);
  }

  private async submitDeviceToken(deviceId: string, userId: string) {
    await this.processMMQPRequest(
      'submitToken',
      'mobileSubmitDeviceToken.xevent',
      { deviceUniq: deviceId, deviceToken: userId, }
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

  private async processMMQPRequest<T extends keyof TMMQPRequestTypes>(
    requestType: T,
    endpoint: TMMQPRequestTypes[T]['endpoint'],
    payload: TMMQPRequestTypes[T]['payload']
  ): Promise<TMMQPRequestTypes[T]['response']> {
    const params = {
      ...defaultMQPPRequestParams,
      MMQP_request: requestType,
    };

    const formData = new URLSearchParams();
    for (const [ key, value, ] of Object.entries({ ...defaultMQPPRequestPayload, ...payload, })) {
      formData.append(key, String(value));
    }

    const { data, } = await this.client.post<TMMQPRequestTypes[T]['response']>(
      endpoint,
      formData.toString(),
      { params, }
    );

    return data;
  }

  private async processBundledMMQPRequest<T extends keyof TMMQPBundledRequestTypes>(
    requestType: T,
    task: TMMQPBundledRequestTypes[T]['task'],
    service: TMMQPBundledRequestTypes[T]['service'],
    args: TMMQPBundledRequestTypes[T]['args']
  ) {
    const request = {
      id: String(Date.now()),
      args,
      task,
      service,
    };

    const result = await this.processMMQPRequest(
      requestType,
      'mobileBundledService.xevent',
      {
        deviceUniq: this.deviceId!,
        input: JSON.stringify([ request, ]),
      }
    );

    debugger;
  }

  private async processRequest<T extends keyof TProcessRequestTypes>(
    requestType: T,
    responseKey: TProcessRequestTypes[T]['responseKey'],
    payload: TProcessRequestTypes[T]['payload']
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
