import axios from 'axios';
import { randomUUID } from 'crypto';
import jsonwebtoken, { JwtPayload } from 'jsonwebtoken';
import Logger from '@ftim/logger';
const logger = Logger.ns('Auth');

import { EBaseUrl, EIntuitHeaderName, EMagicValues, ETokenGrantType, defaultHeaders } from './_constants';
import { EAuthChallengeType, EOTPAuthChallengeType, TAuthEvents, TEvaluateAuthResponse, TOAuthAuthorizationCodeResponse, TOAuthClientCredentialsResponse, TVerifySignInResponse } from './_types';
import { TypedEventEmitter } from '@ftim/typed-event-emitter';
import { SessionStore } from '../common/session-store';
import { Lock } from '../common/lock';

export type TAuthClientOptions = {
  sessionStore: SessionStore
  username: string,
  password: string,
};

const AUTH_CLIENT_LOCK = new Lock('auth-client');

export class AuthClient extends TypedEventEmitter<TAuthEvents> {
  private deviceId: string = randomUUID();

  private sessionStore: SessionStore;
  private username: string;
  private password: string;

  private authorizationCode?: TOAuthAuthorizationCodeResponse;

  constructor({ sessionStore, username, password, }: TAuthClientOptions) {
    super();

    this.sessionStore = sessionStore;
    this.username = username;
    this.password = password;
  }

  private get refreshTokenExpiresAt() {
    return this.authorizationCode?.refresh_token_expires_at ?? new Date(0);
  }

  private get accessTokenExpiresAt() {
    if (!this.authorizationCode) {
      return new Date(0);
    }

    const decoded = jsonwebtoken.decode(this.authorizationCode.access_token) as JwtPayload;

    const expiresAt = decoded?.exp ?? 0;

    return new Date(expiresAt * 1_000);
  }

  getUsername() {
    return this.username;
  }

  async getAccessToken() {
    if (!this.authorizationCode || this.refreshTokenExpiresAt < new Date()) {
      this.authorizationCode = await AUTH_CLIENT_LOCK.runWithLock(
        () => this.authenticate()
      );

      this.emit('authenticated', this.authorizationCode);

      this.sessionStore.set('auth', {
        deviceId: this.deviceId,
        refreshToken: this.authorizationCode.refresh_token,
        refreshTokenExpiresAt: this.refreshTokenExpiresAt.getTime(),
      });
    }

    if (this.accessTokenExpiresAt < new Date()) {
      await AUTH_CLIENT_LOCK.runWithLock(
        () => this.refreshAuthorizationCode(this.authorizationCode?.refresh_token ?? '')
          .then(authorizationCode => {
            this.authorizationCode = authorizationCode;

            this.emit('authorizationCodeRefreshed', this.authorizationCode);
          })
          .catch(async error => {
            logger.error('Failed to refresh authorization code', error);

            this.authorizationCode = await this.authenticate(true);

            this.emit('authenticated', this.authorizationCode);
          })
      );

      this.sessionStore.set('auth', {
        deviceId: this.deviceId,
        refreshToken: this.authorizationCode.refresh_token,
        refreshTokenExpiresAt: this.refreshTokenExpiresAt.getTime(),
      });
    }

    return this.authorizationCode.access_token;
  }

  private async authenticate(bypassSessionStore = false) {
    logger.info('Authenticating...');

    if (!bypassSessionStore) {
      const hydratedAuthorizationCode = await this.hydrateFromSessionStore();
      if (hydratedAuthorizationCode) {
        return hydratedAuthorizationCode;
      }
    }

    const flowId = randomUUID().toUpperCase();

    const firstEvalResult = await this.evaluateAuth(flowId);
    if (firstEvalResult.action === 'PASS') {
      const authorizationCode = await this.createAuthorizationCode(firstEvalResult.oauth2CodeResponse.code);

      return authorizationCode;
    }

    const primaryChallenge = firstEvalResult.challenge.find(({ primary, }) => primary);
    if (!primaryChallenge) {
      throw new Error('No primary challenge found');
    }

    if (primaryChallenge.type !== EAuthChallengeType.PASSWORD) {
      throw new Error(`Primary challenge is not password: ${primaryChallenge.type}`);
    }

    const challengeResult = await this.submitPasswordChallenge(flowId, firstEvalResult.authContextId);

    const secondEvalResult = await this.evaluateAuth(flowId, challengeResult.oauth2CodeResponse.code);

    if (secondEvalResult.action !== 'PASS') {
      throw new Error('Second evaluation failed');
    }

    const authorizationCode = await this.createAuthorizationCode(secondEvalResult.oauth2CodeResponse.code);

    return authorizationCode;
  }

  private async deauthenticate() {
    logger.info('Deauthenticating...');

    const refreshToken = this.authorizationCode?.refresh_token;
    if (!refreshToken) { return; }

    await this.revokeBearerToken(refreshToken)
      .catch(() => logger.error('Failed to revoke bearer token'));

    this.authorizationCode = undefined;

    this.sessionStore.set('auth', undefined);

    this.emit('deauthenticated', null);
  }

  private async createClientCredentials() {
    const data = await this.createBearerToken<TOAuthClientCredentialsResponse>({
      grant_type: ETokenGrantType.CLIENT_CREDENTIALS,
    });

    return data;
  }

  private async createAuthorizationCode(authCode: string) {
    const data = await this.createBearerToken<Omit<TOAuthAuthorizationCodeResponse, 'refresh_token_expires_at'>, { code: string, redirect_uri: string }>({
      code: authCode,
      grant_type: ETokenGrantType.AUTHORIZATION_CODE,
      redirect_uri: EMagicValues.OAUTH_REDIRECT_URI,
    });

    return {
      ...data,
      refresh_token_expires_at: new Date(Date.now() + (data.x_refresh_token_expires_in * 1_000)),
    };
  }

  private async refreshAuthorizationCode(refresh_token: string) {
    const data = await this.createBearerToken<Omit<TOAuthAuthorizationCodeResponse, 'refresh_token_expires_at'>, { refresh_token: string }>({
      refresh_token,
      grant_type: ETokenGrantType.REFRESH_TOKEN,
    });

    return {
      ...data,
      refresh_token_expires_at: new Date(Date.now() + (data.x_refresh_token_expires_in * 1_000)),
    };
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

  private async revokeBearerToken(token: string) {
    await axios.post<void>(
      '/oauth2/v1/tokens/revoke',
      new URLSearchParams({ token, }).toString(),
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
  }

  private async evaluateAuth(flowId: string, authCode?: string) {
    const { access_token, } = authCode ? await this.createAuthorizationCode(authCode) : await this.createClientCredentials();

    logger.info(`Evaluating auth for ${this.username}...`);

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
              value: this.username,
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
          [EIntuitHeaderName.FLOW_ID]: flowId,
          [EIntuitHeaderName.TID]: randomUUID(),
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'sms_otp voice_otp email_otp totp password pwd_reset collect_password collect_recovery_phone collect_confirm_recovery_phone collect_recovery_email collect_recovery_email_or_phone post_auth_challenges consent_7216_ty18 username_reset select_account ar_oow_kba captcha care',
          [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
        },
      }
    );

    logger.info(`Evaluated auth for ${this.username}: ${data.action}`);

    return data;
  }

  private async submitPasswordChallenge(flowId: string, authContextId: string) {
    const result = await this.submitChallenge(flowId, authContextId, EAuthChallengeType.PASSWORD, this.password)
      .catch(error => {
        const responseCode = error.response?.data?.responseCode;

        if (responseCode === 'INVALID_CREDENTIALS') {
          throw new Error('Invalid credentials');
        }

        throw new Error(`Failed to submit password challenge: ${responseCode}`);
      });

    return result;
  }

  private async submitChallenge(flowId: string, authContextId: string, type: EAuthChallengeType, value: string) {
    const { access_token, } = await this.createClientCredentials();

    logger.info(`Submitting challenge for ${type}...`);

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
          [EIntuitHeaderName.FLOW_ID]: flowId,
          [EIntuitHeaderName.TID]: randomUUID(),
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'post_auth_challenges consent_7216_ty18 pwd_reset username_reset',
          [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
        },
      }
    );

    logger.info(`Submitted challenge for ${type}; risk level: ${data.riskLevel}, status: ${data.oauth2CodeResponse.error}`);

    return data;
  }

  private async requestOTPToken(flowId: string, authContextId: string, type: EOTPAuthChallengeType) {
    const { access_token, } = await this.createClientCredentials();

    logger.info(`Requesting ${type} type OTP...`);

    const payload = {
      challengeToken: [
        { type, },
      ],
    };

    await axios.post(
      'v2/oauth2codes/send_sign_in_confirmation',
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
          [EIntuitHeaderName.FLOW_ID]: flowId,
          [EIntuitHeaderName.TID]: randomUUID(),
          [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
        },
      }
    );
  }

  private async hydrateFromSessionStore() {
    logger.info('Hydrating from session store...');

    const authStore = this.sessionStore.get('auth');
    if (!authStore) { return; }

    const { deviceId, refreshToken, refreshTokenExpiresAt, } = authStore;

    if (!deviceId || !refreshToken || !refreshTokenExpiresAt) {
      logger.info('One or more values are missing from auth store');

      return;
    }

    if (refreshTokenExpiresAt < Date.now()) {
      logger.info('Stored refresh token has expired');

      return;
    }

    this.deviceId = deviceId;

    logger.info('Validating stored credentials...');

    const authorizationCode = await this.refreshAuthorizationCode(refreshToken)
      .catch(error => {
        logger.info(`Failed to refresh stored authorization code: ${error.message}`);

        return;
      });

    return authorizationCode;
  }
}
