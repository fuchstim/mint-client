import type { GetRegularUserBudgetsWithSpendSummaryQuery } from './queries/getBudgetSummary';
import type { MintOverviewChartQuery } from './queries/getOverviewChart';

type TQuery<Q, V, R> = {
  query: Q;
  variables: V;
  response: R;
};

type TGetBudgetSummaryQuery = TQuery<
  typeof GetRegularUserBudgetsWithSpendSummaryQuery,
  {
    budgetFilter: {
      endDate: string,
      startDate: string,
    },
    budgetSortOrder: null,
    spendSummaryFilter: {
      endDate: string,
      startDate: string,
    },
    unbudgetedExpenseFilter: {
      endDate: string,
      startDate: string,
    },
  },
  unknown
>;

type TGetOverviewChartQuery = TQuery<
  typeof MintOverviewChartQuery,
  {
    categoryId: null,
    currentDate: string,
    reportType: 'SPENDING' | 'NETWORTH',
    timeframe: '_7D' | '_30D' | '_1Y' | 'ALL',
  },
  unknown
>;

export type TQueries = {
  ['GetRegularUserBudgetsWithSpendSummary']: TGetBudgetSummaryQuery,
  ['MintOverviewChart']: TGetOverviewChartQuery,
};
