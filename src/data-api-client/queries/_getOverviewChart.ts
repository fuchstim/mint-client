import dayjs from '../../common/dayjs';

import type { TQuery } from '.';

const query = /* GraphQL */`
  query MintOverviewChart($currentDate: String!, $reportType: String, $timeframe: MintMercuryChartTimeframeType, $categoryId: Int) {
    consumer {
      finance {
        mintOverviewChart(
          currentDate: $currentDate
          reportType: $reportType
          timeframe: $timeframe
          categoryId: $categoryId
        ) {
          currency
          currentDate
          delta
          dataPoints {
            date
            value
          }
          customDataPoints {
            date
            value
          }
          lookAlikeDataPoints {
            date
            value
          }
          forecastDataPoints {
            date
            value
          }
          forecastedSpendingCategories {
            categoryId
            value
            budgetAmount
            amount
          }
          topCategories {
            amount
            categoryId
            eomAmount
            percentage
            value
          }
          topOverBudgetCategories {
            amount
            budgetAmount
            categoryId
            eomAmount
            value
          }
          categoryId
          heroMainValue
          reportType
          subHeaderText
          subHeaderValue
          timeframe
        }
      }
    }
  }
`;

export enum EReportType {
  SPENDING = 'SPENDING',
}

export enum ETimeframe {
  MONTH = '_30D',
}

export default {
  operationName: 'MintOverviewChart',
  query,
  toVariables: ({ date, reportType, timeframe, }) => ({
    categoryId: null,
    currentDate: dayjs(date).format('YYYY-MM-DD'),
    reportType,
    timeframe,
  }),
} as TQuery<
  { date: Date, reportType: EReportType, timeframe: ETimeframe, },
  { categoryId: null, currentDate: string, reportType: string, timeframe: string, }
>;
