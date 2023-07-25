import axios, { AxiosInstance } from 'axios';
import { randomUUID } from 'crypto';

import { BASE_URL, EIntuitHeaderName, EMagicValues, ETokenGrantType } from './_constants';
import { TOAuthAuthorizationCodeResponse, TOAuthClientCredentialsResponse, TOAuthRegisterDeviceResponse } from './_types';

class OAuthClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: BASE_URL,
      headers: {
        Accept: '*/*',
        'Accept-Language': 'en-ca',
        'User-Agent': 'com.intuit.identity.IntuitAuthorization/7.27.2(1) com.mint.internal/150.70.0(1.24203) iOS/16.5.1',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        [EIntuitHeaderName.DEVICE_INFO]: '{"mobile":true,"os":"iOS 16.5.1","model":"iPhone15,2","platform":"iOS","userAgent":"com.intuit.identity.IntuitAuthorization\/7.27.2(1) com.mint.internal\/150.70.0(1.24203) iOS\/16.5.1","name":"iPhone","make":"Apple"}',
        [EIntuitHeaderName.COUNTRY]: 'CA',
        [EIntuitHeaderName.LOCALE]: 'en-ca',
        [EIntuitHeaderName.OFFERING_ID]: 'Intuit.ifs.mint.3',
      },
    });

    this.client.interceptors.request.use(request => {
      request.headers.set(EIntuitHeaderName.TID, randomUUID());

      return request;
    });
  }

  async registerDevice(deviceId: string) {
    const payload = {
      x_app_token: EMagicValues.APP_TOKEN,
      x_client_context: 'Device Name: "iPhone" | Model: "iPhone15,2"',
    };

    const { data, } = await this.client.post<TOAuthRegisterDeviceResponse>(
      '/oauth2/v1/clients',
      payload,
      { headers: { [EIntuitHeaderName.DEVICE_ID]: deviceId, }, }
    );

    return {
      clientId: data.client_id,
      clientSecret: data.client_secret,
    };
  }

  async createClientCredentials(deviceId: string, clientId: string, clientSecret: string) {
    const data = await this.createBearerToken<TOAuthClientCredentialsResponse>(
      deviceId,
      clientId,
      clientSecret,
      { grant_type: ETokenGrantType.CLIENT_CREDENTIALS, }
    );

    return data;
  }

  async createAuthorizationCode(deviceId: string, clientId: string, clientSecret: string, authCode: string) {
    const data = await this.createBearerToken<TOAuthAuthorizationCodeResponse, { code: string, redirect_uri: string }>(
      deviceId,
      clientId,
      clientSecret,
      {
        code: authCode,
        grant_type: ETokenGrantType.AUTHORIZATION_CODE,
        redirect_uri: EMagicValues.REDIRECT_URI,
      }
    );

    return data;
  }

  async refreshAuthorizationCode(deviceId: string, clientId: string, clientSecret: string, refreshToken: string) {
    const data = await this.createBearerToken<TOAuthAuthorizationCodeResponse, { refresh_token: string }>(
      deviceId,
      clientId,
      clientSecret,
      { refresh_token: refreshToken, grant_type: ETokenGrantType.REFRESH_TOKEN, }
    );

    return data;
  }

  private async createBearerToken<R, P = Record<string, string>>(
    deviceId: string,
    clientId: string,
    clientSecret: string,
    payload: P & { grant_type: ETokenGrantType }
  ) {
    const { data, } = await this.client.post<R>(
      '/oauth2/v1/tokens/bearer',
      new URLSearchParams(payload).toString(),
      {
        auth: { username: clientId, password: clientSecret, },
        headers: { [EIntuitHeaderName.DEVICE_ID]: deviceId, },
      }
    );

    return data;
  }

  async revokeBearerToken(deviceId: string, clientId: string, clientSecret: string, token: string) {
    await this.client.post(
      '/oauth2/v1/tokens/revoke',
      new URLSearchParams({ token, }).toString(),
      {
        auth: { username: clientId, password: clientSecret, },
        headers: { [EIntuitHeaderName.DEVICE_ID]: deviceId, },
      }
    );
  }
}

export default new OAuthClient();
