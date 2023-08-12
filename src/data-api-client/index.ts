import axios, { AxiosInstance } from 'axios';
import { randomUUID } from 'crypto';

import type AuthClient from '../auth';
import dayjs from '../common/dayjs';

import { BASE_URL, EIntuitHeaderName, defaultHeaders } from './_constants';
import type { TQueries } from './_types';

import { GetRegularUserBudgetsWithSpendSummaryQuery } from './queries/getBudgetSummary';
import { MintOverviewChartQuery } from './queries/getOverviewChart';

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

  async getBudgetSummary(options: { date: Date }) {
    const { date, } = options;

    const firstOfMonth = dayjs(date).startOf('month').format('YYYY-MM-DD');

    const variables = {
      budgetFilter: {
        endDate: firstOfMonth,
        startDate: firstOfMonth,
      },
      budgetSortOrder: null,
      spendSummaryFilter: {
        endDate: firstOfMonth,
        startDate: firstOfMonth,
      },
      unbudgetedExpenseFilter: {
        endDate: firstOfMonth,
        startDate: firstOfMonth,
      },
    };

    const budgetSummary = await this.query(
      'GetRegularUserBudgetsWithSpendSummary',
      GetRegularUserBudgetsWithSpendSummaryQuery,
      variables
    );

    return budgetSummary.data;
  }

  async getOverviewChart(options: {
    date: Date,
    reportType: TQueries['MintOverviewChart']['variables']['reportType'],
    timeframe: TQueries['MintOverviewChart']['variables']['timeframe']
  }) {
    const { date, reportType, timeframe, } = options;

    const variables = {
      categoryId: null,
      currentDate: dayjs(date).format('YYYY-MM-DD'),
      reportType,
      timeframe,
    };

    const overviewChart = await this.query(
      'MintOverviewChart',
      MintOverviewChartQuery,
      variables
    );

    return overviewChart.data;
  }

  private async query<N extends keyof TQueries>(
    operationName: N,
    query: TQueries[N]['query'],
    variables: TQueries[N]['variables']
  ): Promise<TQueries[N]['response']> {
    const { data, } = await this.client.post<TQueries[N]['response']>(
      'graphql',
      { operationName, query, variables, },
      { headers: { 'X-APOLLO-OPERATION-NAME': operationName, }, }
    );

    return data;
  }
}
