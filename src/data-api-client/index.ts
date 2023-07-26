import axios, { AxiosInstance } from 'axios';
import { randomUUID } from 'crypto';

import type AuthClient from '../auth';
import dayjs from '../common/dayjs';

import { BASE_URL, EIntuitHeaderName, defaultHeaders } from './_constants';
import { queries } from './queries';

type TQueries = typeof queries;

export default class DataApiClient {
  private client: AxiosInstance;

  constructor(authClient: AuthClient) {
    this.client = axios.create({
      baseURL: BASE_URL,
      headers: defaultHeaders,
    });

    this.client.interceptors.request.use(async request => {
      const requestId = randomUUID().toUpperCase();
      const accessToken = await authClient.getAccessToken();

      request.headers.set('Authorization', `Bearer ${accessToken}`);
      request.headers.set('Device-Time-Offset', dayjs().format('YYYY-MM-DDTHH:mm:ss.SSS'));
      request.headers.set(EIntuitHeaderName.REQUEST_ID, requestId);
      request.headers.set(EIntuitHeaderName.TID, requestId);

      return request;
    });
  }

  async query<T extends keyof TQueries>(
    queryName: T,
    parameters: Parameters<TQueries[T]['toVariables']>[0]
  ) {
    const { operationName, query, toVariables, } = queries[queryName];

    const { data, } = await this.client.post(
      'graphql',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { operationName, query, variables: toVariables(parameters as any), },
      {
        headers: { 'X-APOLLO-OPERATION-NAME': operationName, },
      }
    );

    return data;
  }
}
