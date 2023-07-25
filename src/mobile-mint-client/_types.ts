import { UUID } from 'crypto';

export type TGetNewUuidResponse = {
  uuid: UUID
};

export type TRegisterUserResponse = {
  versionValidity: string,
  entitlements: string,
  responseType: string,
  mpxvErrorId: string,
  protocolValidity: string,
  guid: string,
  mintPN: string,
  currentProtocol: string,
  userId: number,
  currentVersion: string,
  token: string,
};

export type TUserDataResponse = {
  entitlements: string,
  totalBudget: number,
  configuration: Record<string, number>,
  isIAMUser: string,
  protocolValidity: string,
  allBudgets: boolean,
  versionValidity: string,
  features: Record<string, boolean>,
  responseType: string,
  categories: {
    categoryType: string,
    depth: string,
    unassignable: boolean,
    id: number,
    softDeleted: boolean,
    categoryName: string,
    parentId: number
  }[],
  isInMintNamespace: string,
  manualTxns: never[],
  profile: {
    zipcode: string,
    country: string,
    dateFormat: string,
    timezone: string,
    currency: string,
    email: string,
    authId: number
  },
  dataType: 'primary',
  cashFlow: {
    income: number,
    expenses: number,
  },
  advices: never[],
  currentProtocol: string,
  currentVersion: string,
  fiLogins: {
    isManual: string,
    mintStatus: number,
    isHostFiLogin: string,
    contentProviderType: string,
    url: string,
    lastUpdated: string,
    fiName: string,
    supplementalLink: string,
    phone: string | null,
    logo: string | null,
    lastUpdatedTime: number,
    fiLoginId: number,
    supplementalText: string
  }[],
  tags: {
      name: string,
      isHiddenFromPlanningTrends: boolean,
      id: number,
      isHidden: boolean,
    }[],
  alerts: {
    date: number,
    alertTypeString: string,
    amount: number | null,
    alertType: number,
    smallImageUrl: string | null,
    extraLargeImgUrl: string | null,
    accountId: number,
    categoryIds: number[] | null,
    viewed: boolean,
    details: string,
    id: number,
    categoryId: number | null,
    largeImgUrl: string | null,
    alertCategory: number,
  }[],
  budgets: {
    amount: number,
    period: null,
    dateString: string,
    budgetPerformance: number,
    type: string,
    paymentDateString: string,
    totalAmount: number | null,
    budgetAmount: number,
    rollover: boolean,
    id: number,
    categoryId: number,
    status: number,
  }[],
  baseURI: string,
  accounts: [
    {
      linkedAccountId: number | null,
      accountName: string,
      ccAggrStatus:number,
      accountType:number,
      subAccountType: string,
      numTransactions:number,
      isHiddenFromPlanningTrends: false,
      accountNumber: string,
      accountStatus:number,
      accountId:number,
      balance:number,
      modified:number,
      currency: string,
      fiLoginId:number,
      isHiddenLinkedAccount: boolean
    },
  ],
  lastModified: number
};

export type TMMQPRequestType<E extends string, P, R> = {
  endpoint: E,
  payload: P,
  response: R
};

export type TMMQPRequestTypes = TMMQPBundledRequestTypes & {
  registerUser: TMMQPRequestType<
    'mobileLogin.xevent',
    { deviceUniq: string },
    TRegisterUserResponse
  >,
  submitToken: TMMQPRequestType<
    'mobileSubmitDeviceToken.xevent',
    { deviceUniq: string, deviceToken: string },
    void
  >,
  UserData_primary: TMMQPRequestType<
    'mobileData.xevent',
    {
      deviceUniq: string,
      countAsLogin: boolean,
      isManualTransactionsRequest: boolean,
      getBudgets: boolean,
      dataType: 'primary',
      allBudgets: boolean,
    },
    TUserDataResponse
  >,
};

export type TMMQBundledRequestType<T extends string, S extends string, A, R> = TMMQPRequestType<
  'mobileBundledService.xevent',
  { input: string, deviceUniq: string },
  {
    versionValidity: string,
    responseType: string,
    response: Record<
      string,
      { duration: number, responseType: string, callStatus: string, response: R }
    >
  }
> & {
  args: A,
  task: T,
  service: S,
};

export type TMMQPBundledRequestTypes = {
  fetchModifiedTransactions: TMMQBundledRequestType<
    'getModifiedTransactions',
    'MintUserMobileService',
    { visibleDateFrom?: number, visibleDateTo?: number, accountIDs: number[], maxCount: number },
    {
      visibleDateFrom: number,
      visibleDateTo: number,
      hasEarlierTransactions: boolean,
      totalCountInFullResult: number,
      modifiedFrom: number | null,
      transactions: unknown[],
      earliestVisibleDateInFullResult: number,
      modifiedTo: number,
     }
  >
};

export enum ECategoryType {
  EXPENSE = 'e',
  INCOME = 'i',
  NEITHER = 'n',
}

export type TCategory = {
  id: number,
  categoryType: ECategoryType,
  depth: number,
  categoryName: string,
  notificationName: string,
  parentId: number,
  precedence: number,
  standard: boolean,
  modified: number,
  isBusiness: boolean,
  categoryFamily: string
};

export type TProcessRequestType<K extends string, P, R> = {
  responseKey: K,
  payload: P,
  response: R
};

export type TProcessRequestTypes = {
  getCategories: TProcessRequestType<
    'categoriesResponse',
    { includeDeletedCategories: boolean, modifiedFrom: string },
    { entries: TCategory[] }
  >
};
