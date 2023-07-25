export const MAX_AUTH_ATTEMPTS = 5;

export const BASE_URL = 'https://access.platform.intuit.com';

export enum EIntuitHeaderName {
  DEVICE_INFO = 'intuit_device_info',
  COUNTRY = 'intuit_country',
  LOCALE = 'intuit_locale',
  OFFERING_ID = 'intuit_offeringid',
  TID = 'intuit_tid',
  DEVICE_ID = 'intuit_deviceid',
  FLOW_ID = 'intuit_flowid',
  RISK_PROFILING_DATA = 'intuit_risk_profiling_data',
  ACCEPT_AUTH_CHALLENGE = 'intuit_accept_authchallenge',
  AUTH_CONTEXT_ID = 'intuit_auth_context_id',
  CAPTCHA_RESPONSE = 'intuit_captcha_response',
}

export enum EMagicValues {
  OAUTH_APP_TOKEN = 'PlHjhpsIJTZNfCAnXSLbJhMfyUzz04Oy0cBi2Ua6hFJoxiLyYt',
  OAUTH_REDIRECT_URI = 'https://oauth2.intuit.com/nativeredirect/v1',
  RISK_PROFILING_DATA = '880c2310-4440-11e4-916c-0800200c9a66&27BBAC644862455C0B63B0B3607DA027',
  // RISK_PROFILING_DATA = '880c2310-4440-11e4-916c-0800200c9a66&e32c2242-aa51-4751-bd71-751820cd3431',
  NAMESPACE_ID = '50000026',
}
