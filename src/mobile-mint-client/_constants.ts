export const BASE_URL = 'https://mobile.mint.com' as const;

export const defaultHeaders = {
  Accept: 'text/html,application/xhtml+xml,application/xml, text/json',
  'Accept-Language': 'en-CA,en-US;q=0.9,en;q=0.8',
  'User-Agent': 'Mint/1.24203 CFNetwork/1408.0.4 Darwin/22.5.0',
} as const;

export const defaultMQPPRequestParams = {
  MMQP_platform: 'iPhone',
  MMQP_protocol: '150.70.0',
  MMQP_version: '150.70.0',
} as const;

export const defaultMQPPRequestPayload = {
  buildNumber: '1.24203',
  clientType: 'Mint',
  demo: 'false',
  deviceLocalModel: 'iPhone',
  deviceModel: 'iPhone',
  deviceModelID: 'iPhone15,2',
  deviceName: 'iPhone',
  deviceSysName: 'iOS',
  deviceSysVersion: '16.5.1',
  platform: 'iphone',
  protocol: '150.70.0',
  version: '150.70.0',
} as const;

