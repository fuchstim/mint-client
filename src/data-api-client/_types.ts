import type { GetRegularUserBudgetsWithSpendSummaryQuery } from './queries/getBudgetSummary';
import type { MintOverviewChartQuery } from './queries/getOverviewChart';

type TQuery<Q, V, R> = {
  query: Q;
  variables: V;
  response: R;
};

type TGetBudgetSummaryQueryVariables = {
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
};

type TGetBudgetSummaryQueryResponse = {
  data: {
    consumer: {
      finance: {
        budgets: {
          userBudgets: {
            id: string,
            budgetDate: string,
            budgetType: string,
            amount: number,
            budgetAmount: number,
            subsumed: boolean,
            performanceStatus: string,
            budgetInterval: string,
            source: {
              id: string,
              type: string,
              categoryName: string,
              categoryType: string,
              parentId: string,
              parentName: string,
            },
            budgetAdjustmentAmount: null | unknown,
            reset: boolean,
            rollover: boolean,
          }[],
          unbudgetedExpenses: {
            categoryId: string,
            category: {
              id: string,
              name: string,
              parentId: string,
              type: string,
              parentName: string,
            },
            amount: number,
            date: string,
          }[],
          spendSummary: {
            budgetedLeftOverCash: number,
            month: string,
            totalBudgetedIncome: number,
            totalBudgetedSpending: number,
            totalExpensesBudget: number,
            totalIncomeBudget: number,
            totalUnbudgetedIncome: number,
            totalUnbudgetedSpending: number,
            leftOverCash: number,
            totalIncome: number,
            totalSpending: number,
          }[],
        },
      },
    },
  },
};

type TGetBudgetSummaryQuery = TQuery<
  typeof GetRegularUserBudgetsWithSpendSummaryQuery,
  TGetBudgetSummaryQueryVariables,
  TGetBudgetSummaryQueryResponse
>;

type TGetOverviewChartQueryVariables = {
  categoryId: null,
  currentDate: string,
  reportType: 'SPENDING' | 'NETWORTH',
  timeframe: '_7D' | '_30D' | '_1Y' | 'ALL',
};

type TGetOverviewChartQueryResponse = {
  data: {
    consumer: {
      finance: {
        mintOverviewChart: {
          currency: string,
          currentDate: string,
          delta: null | unknown,
          dataPoints: {
            date: string,
            value: number,
          }[],
          customDataPoints: {
            date: string,
            value: number,
          }[],
          lookAlikeDataPoints: {
            date: string,
            value: number,
          }[],
          forecastDataPoints: {
            date: string,
            value: number,
          }[],
          forecastedSpendingCategories: unknown[],
          topCategories: unknown[],
          topOverBudgetCategories: unknown[],
          categoryId: null | unknown,
          heroMainValue: number,
          reportType: string,
          subHeaderText: null | unknown,
          subHeaderValue: null | unknown,
          timeframe: string,
        },
      },
    },
  },
};

type TGetOverviewChartQuery = TQuery<
  typeof MintOverviewChartQuery,
  TGetOverviewChartQueryVariables,
  TGetOverviewChartQueryResponse
>;

export type TQueries = {
  ['GetRegularUserBudgetsWithSpendSummary']: TGetBudgetSummaryQuery,
  ['MintOverviewChart']: TGetOverviewChartQuery,
};
