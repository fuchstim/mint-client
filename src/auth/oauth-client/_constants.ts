export const BASE_URL = 'https://oauth.platform.intuit.com';

export enum EIntuitHeaderName {
  DEVICE_INFO = 'intuit_device_info',
  COUNTRY = 'intuit_country',
  LOCALE = 'intuit_locale',
  OFFERING_ID = 'intuit_offeringid',
  TID = 'intuit_tid',
  DEVICE_ID = 'intuit_deviceid',
}

export enum ETokenGrantType {
  CLIENT_CREDENTIALS = 'client_credentials',
  AUTHORIZATION_CODE = 'authorization_code',
  REFRESH_TOKEN = 'refresh_token'
}

export enum EMagicValues {
  APP_TOKEN = 'PlHjhpsIJTZNfCAnXSLbJhMfyUzz04Oy0cBi2Ua6hFJoxiLyYt',
  REDIRECT_URI = 'https://oauth2.intuit.com/nativeredirect/v1',
  CLIENT_CONTEXT = 'Device Name: "iPhone" | Model: "iPhone15,2"',
}
