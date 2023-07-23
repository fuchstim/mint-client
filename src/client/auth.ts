import axios from 'axios';
import { randomUUID } from 'crypto';

import { EBaseUrl, EIntuitHeaderName, EMagicValues, ETokenGrantType, defaultHeaders } from './constants';
import { EAuthChallengeType, TEvaluateAuthResponse, TOAuthAuthorizationCodeResponse, TOAuthClientCredentialsResponse, TVerifySignInResponse } from './types';

export class AuthClient {
  private deviceId: string = randomUUID();

  async authenticate(identifier: string, password: string) {
    const firstEvalResult = await this.evaluateAuth(identifier);
    if (firstEvalResult.action === 'PASS') {
      throw new Error('Already authenticated');
    }

    const primaryChallenge = firstEvalResult.challenge.find(({ primary, }) => primary);
    if (!primaryChallenge) {
      throw new Error('No primary challenge found');
    }

    if (primaryChallenge.type !== EAuthChallengeType.PASSWORD) {
      throw new Error(`Primary challenge is not password: ${primaryChallenge.type}`);
    }

    const challengeResult = await this.submitChallenge(firstEvalResult.authContextId, primaryChallenge.type, password);

    const secondEvalResult = await this.evaluateAuth(identifier, challengeResult.oauth2CodeResponse.code);

    if (secondEvalResult.action !== 'PASS') {
      throw new Error('Second evaluation failed');
    }

    const authorizationCode = await this.createAuthorizationCode(secondEvalResult.oauth2CodeResponse.code);

    return authorizationCode;
  }

  private async createClientCredentials() {
    const data = await this.createBearerToken<TOAuthClientCredentialsResponse>({
      grant_type: ETokenGrantType.CLIENT_CREDENTIALS,
    });

    return data;
  }

  private async createAuthorizationCode(code: string) {
    const data = await this.createBearerToken<TOAuthAuthorizationCodeResponse, { code: string, redirect_uri: string }>({
      code,
      grant_type: ETokenGrantType.AUTHORIZATION_CODE,
      redirect_uri: EMagicValues.OAUTH_REDIRECT_URI,
    });

    return data;
  }

  private async createBearerToken<R, P = Record<string, string>>(params: P & { grant_type: ETokenGrantType }) {
    const { data, } = await axios.post<R>(
      '/oauth2/v1/tokens/bearer',
      new URLSearchParams(params).toString(),
      {
        baseURL: EBaseUrl.AUTH_OAUTH,
        auth: {
          username: EMagicValues.OAUTH_CLIENT_ID,
          password: EMagicValues.OAUTH_CLIENT_SECRET,
        },
        headers: {
          ...defaultHeaders.auth,
          Accept: '*/*',
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          [EIntuitHeaderName.DEVICE_ID]: this.deviceId,
          [EIntuitHeaderName.TID]: randomUUID(),
        },
      }
    );

    return data;
  }

  private async evaluateAuth(identifier: string, authCode?: string) {
    const { access_token, } = authCode ? await this.createAuthorizationCode(authCode) : await this.createClientCredentials();

    const payload = {
      oauth2CodeRequest: {
        clientId: EMagicValues.OAUTH_CLIENT_ID,
        redirectUri: EMagicValues.OAUTH_REDIRECT_URI,
      },
      policies: [
        {
          name: 'IDENTIFIER_FIRST',
          attributes: [
            {
              key: 'identifier',
              value: identifier,
            },
            {
              key: 'namespaceId',
              value: '50000026',
            },
            {
              key: 'identifierTypes',
              value: 'email,username',
            },
          ],
        },
      ],
    };

    const { data, } = await axios.post<TEvaluateAuthResponse>(
      'v2/oauth2codes/evaluate_auth',
      payload,
      {
        baseURL: EBaseUrl.AUTH_ACCESS_PLATFORM,
        headers: {
          ...defaultHeaders.auth,
          Authorization: `Bearer ${access_token}`,
          Accept: 'application/json',
          'Content-Type': 'application/json',
          [EIntuitHeaderName.DEVICE_ID]: this.deviceId,
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'sms_otp voice_otp email_otp totp password pwd_reset collect_password collect_recovery_phone collect_confirm_recovery_phone collect_recovery_email collect_recovery_email_or_phone post_auth_challenges consent_7216_ty18 username_reset select_account ar_oow_kba captcha care',
          [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
          [EIntuitHeaderName.FLOW_ID]: EMagicValues.OAUTH_FLOW_ID,
        },
      }
    );

    return data;
  }

  private async submitChallenge(authContextId: string, type: EAuthChallengeType, value: string) {
    const { access_token, } = await this.createClientCredentials();

    const payload = {
      challengeToken: [
        { type, value, },
      ],
      oauth2CodeRequest: {
        clientId: EMagicValues.OAUTH_CLIENT_ID,
        redirectUri: EMagicValues.OAUTH_REDIRECT_URI,
      },
    };

    const { data, } = await axios.post<TVerifySignInResponse>(
      'v2/oauth2codes/verify_sign_in_confirmation',
      payload,
      {
        baseURL: EBaseUrl.AUTH_ACCESS_PLATFORM,
        headers: {
          ...defaultHeaders.auth,
          Authorization: `Bearer ${access_token}`,
          Accept: 'application/json',
          'Content-Type': 'application/json',
          [EIntuitHeaderName.DEVICE_ID]: this.deviceId,
          [EIntuitHeaderName.AUTH_CONTEXT_ID]: authContextId,
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'post_auth_challenges consent_7216_ty18 pwd_reset username_reset',
          [EIntuitHeaderName.FLOW_ID]: EMagicValues.OAUTH_FLOW_ID,
          [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
        },
      }
    );

    return data;
  }
}
