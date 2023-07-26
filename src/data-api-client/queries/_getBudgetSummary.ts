import dayjs from '../../common/dayjs';

import type { TQuery } from '.';

const query = /* GraphQL */`
  query GetRegularUserBudgetsWithSpendSummary($budgetFilter: BudgetFilter, $budgetSortOrder: BudgetSortOrder, $unbudgetedExpenseFilter: UnbudgetedExpenseFilter, $spendSummaryFilter: SpendSummaryFilter) {
    consumer {
      finance {
        budgets {
          userBudgets(budgetFilter: $budgetFilter, budgetSortOrder: $budgetSortOrder) {
            ... on RegularBudget {
              id
              budgetDate
              budgetType
              amount
              budgetAmount
              subsumed
              performanceStatus
              budgetInterval
              source {
                id
                ...BudgetCategorySource
              }
              budgetAdjustmentAmount
              reset
              rollover
            }
            ... on AccrualBudget {
              id
              budgetDate
              budgetType
              amount
              budgetAmount
              subsumed
              performanceStatus
              budgetInterval
              source {
                id
                ...BudgetCategorySource
              }
              paymentDate
              period
              scaledBudgetAmount
              totalAccruedAmount
              totalBudgetAmount
            }
            ... on OneTimeBudget {
              id
              budgetDate
              budgetType
              amount
              budgetAmount
              subsumed
              performanceStatus
              budgetInterval
              source {
                id
                ...BudgetCategorySource
              }
              paymentDate
              totalBudgetAmount
              totalAccruedAmount
            }
          }
          unbudgetedExpenses(unbudgetedExpenseFilter: $unbudgetedExpenseFilter) {
            categoryId
            category {
              id
              name
              parentId
              type
              parentName
            }
            amount
            date
          }
          spendSummary(spendSummaryFilter: $spendSummaryFilter) {
            budgetedLeftOverCash
            month
            totalBudgetedIncome
            totalBudgetedSpending
            totalExpensesBudget
            totalIncomeBudget
            totalUnbudgetedIncome
            totalUnbudgetedSpending
            leftOverCash
            totalIncome
            totalSpending
          }
        }
      }
    }
  }
  fragment BudgetCategorySource on CategorySource {
    id
    type
    categoryName
    categoryType
    parentId
    parentName
  }
`;

export default {
  operationName: 'GetRegularUserBudgetsWithSpendSummary',
  query,
  toVariables({ date, }) {
    const firstOfMonth = dayjs(date).startOf('month').format('YYYY-MM-DD');

    return {
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
  },
} as TQuery<
  { date: Date },
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
  }
>;
