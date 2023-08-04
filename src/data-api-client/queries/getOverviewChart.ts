export const MintOverviewChartQuery = /* GraphQL */`
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
` as const;
