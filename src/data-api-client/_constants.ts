export const BASE_URL = 'https://data.api.intuit.com';

export enum EIntuitHeaderName {
  REQUEST_ID = 'intuit_requestid',
  TID = 'intuit_tid',
  APP_ID = 'intuit_appid',
  COUNTRY = 'intuit_country',
  DEVICE_ID = 'intuit_deviceid',
  LOCALE = 'intuit_locale',
  OFFERING_ID = 'intuit_offeringid',
  OFFERING_VERSION = 'intuit_offeringversion',
}

export const defaultHeaders = {
  'Accept-Language': 'en-CA,en-US;q=0.9,en;q=0.8',
  'apollographql-client-name': 'com.mint.internal-apollo-ios',
  'apollographql-client-version': '150.70.0-1.24203',
  'Content-Type': 'application/json',
  'User-Agent': 'Mint/1.24203 CFNetwork/1408.0.4 Darwin/22.5.0',
  'X-APOLLO-OPERATION-TYPE': 'query',
  Accept: '*/*',
  [EIntuitHeaderName.APP_ID]: 'com.mint.internal',
  [EIntuitHeaderName.COUNTRY]: 'US',
  [EIntuitHeaderName.DEVICE_ID]: '00000000-0000-0000-0000-000000000000',
  [EIntuitHeaderName.LOCALE]: 'en_US',
  [EIntuitHeaderName.OFFERING_ID]: 'Intuit.ifs.mint.3',
  [EIntuitHeaderName.OFFERING_VERSION]: '150.70.0',
} as const;
