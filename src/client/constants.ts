export enum EBaseUrl {
  AUTH_OAUTH = 'https://oauth.platform.intuit.com',
  AUTH_ACCESS_PLATFORM = 'https://access.platform.intuit.com'
}

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
}

export enum ETokenGrantType {
  CLIENT_CREDENTIALS = 'client_credentials',
  AUTHORIZATION_CODE = 'authorization_code'
}

export const defaultHeaders = {
  auth: {
    'Accept-Language': 'en-ca',
    'User-Agent': 'com.intuit.identity.IntuitAuthorization/7.27.2(1) com.mint.internal/150.70.0(1.24203) iOS/16.5.1',
    [EIntuitHeaderName.DEVICE_INFO]: '{"mobile":true,"os":"iOS 16.5.1","model":"iPhone15,2","platform":"iOS","userAgent":"com.intuit.identity.IntuitAuthorization\/7.27.2(1) com.mint.internal\/150.70.0(1.24203) iOS\/16.5.1","name":"iPhone","make":"Apple"}',
    [EIntuitHeaderName.COUNTRY]: 'CA',
    [EIntuitHeaderName.LOCALE]: 'en-ca',
    [EIntuitHeaderName.OFFERING_ID]: 'Intuit.ifs.mint.3',
  },
} as const;

export enum EMagicValues {
  OAUTH_CLIENT_ID = 'ABt7u09feDm2ghwiOx0IKSZn4Ka3K7H6y3wsF3ufUZrZandA13',
  OAUTH_CLIENT_SECRET = 'vvvl2NesN8ZaN6hk36BwHXY4J9zeHN2FRa0zH63X',
  OAUTH_FLOW_ID = 'E9A9A395-74D2-49FC-9F5E-701AD70EF66C',
  OAUTH_REDIRECT_URI = 'https://oauth2.intuit.com/nativeredirect/v1',
  RISK_PROFILING_DATA = '880c2310-4440-11e4-916c-0800200c9a66&27BBAC644862455C0B63B0B3607DA027'
}
