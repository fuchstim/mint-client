import getBudgetSummary from './_getBudgetSummary';
import getOverviewChart from './_getOverviewChart';

export type TQuery<P, V> = {
  operationName: string;
  query: string;
  toVariables: (params: P) => V;
};

export const queries = {
  getBudgetSummary,
  getOverviewChart,
} as const;
