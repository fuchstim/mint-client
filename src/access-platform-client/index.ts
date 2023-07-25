import axios, { AxiosInstance } from 'axios';
import { randomUUID } from 'crypto';
import jsonwebtoken, { JwtPayload } from 'jsonwebtoken';
import Logger from '@ftim/logger';
const logger = Logger.ns('Auth');

import { BASE_URL, EIntuitHeaderName, EMagicValues } from './_constants';
import { EAuthChallengeType, EOTPAuthChallengeType, TSession, TEvaluateAuthResponse, TVerifySignInResponse } from './_types';
import { SessionStore } from '../common/session-store';
import { Lock } from '../common/lock';
import oauthClient from '../oauth-client';
import { TOAuthAuthorizationCodeResponse } from '../oauth-client/_types';

export type TAuthClientOptions = {
  sessionStore: SessionStore
  username: string,
  password: string,
};

const ACCESS_PLATFORM_CLIENT_LOCK = new Lock('access-platform-client');

export class AccessPlatformClient {
  private sessionStore: SessionStore;
  private username: string;
  private password: string;

  private client: AxiosInstance;
  private session?: TSession;

  constructor({ sessionStore, username, password, }: TAuthClientOptions) {
    this.sessionStore = sessionStore;
    this.username = username;
    this.password = password;

    this.client = axios.create({
      baseURL: BASE_URL,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'Accept-Language': 'en-ca',
        'User-Agent': 'com.intuit.identity.IntuitAuthorization/7.27.2(1) com.mint.internal/150.70.0(1.24203) iOS/16.5.1',
        [EIntuitHeaderName.DEVICE_INFO]: '{"mobile":true,"os":"iOS 16.5.1","model":"iPhone15,2","platform":"iOS","userAgent":"com.intuit.identity.IntuitAuthorization\/7.27.2(1) com.mint.internal\/150.70.0(1.24203) iOS\/16.5.1","name":"iPhone","make":"Apple"}',
        [EIntuitHeaderName.COUNTRY]: 'CA',
        [EIntuitHeaderName.LOCALE]: 'en-ca',
        [EIntuitHeaderName.OFFERING_ID]: 'Intuit.ifs.mint.3',
        [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
      },
    });

    this.client.interceptors.request.use(request => {
      request.headers.set(EIntuitHeaderName.TID, randomUUID());

      return request;
    });

    this.session = this.hydrateSession();
  }

  private get isAuthenticated() {
    if (!this.session) { return false; }

    const decoded = jsonwebtoken.decode(this.session.accessToken) as JwtPayload;

    const expiresAt = decoded?.exp ?? 0;

    return Date.now() > expiresAt * 1_000;
  }

  getUsername() {
    return this.username;
  }

  async getAccessToken() {
    if (!this.isAuthenticated) {
      this.session = await ACCESS_PLATFORM_CLIENT_LOCK.runWithLock(() => this.refreshOrCreateSession());

      this.sessionStore.set('auth', this.session);
    }

    return this.session!.accessToken;
  }

  private async refreshOrCreateSession() {
    const session = this.refreshSession()
      .catch(() => {
        logger.info('Failed to refresh session, creating new session...');

        return this.createSession();
      });

    return session;
  }

  private async refreshSession() {
    logger.info('Refreshing session...');

    if (!this.session) { throw new Error('No session to refresh'); }

    const { deviceId, clientId, clientSecret, refreshToken, } = this.session;

    const authorizationCode = await oauthClient.refreshAuthorizationCode(deviceId, clientId, clientSecret, refreshToken);

    return this.createSessionFromAuthorizationCode(
      deviceId,
      clientId,
      clientSecret,
      authorizationCode
    );
  }

  private async createSession() {
    logger.info('Creating session...');

    const deviceId = randomUUID();
    const flowId = randomUUID().toUpperCase();

    const { clientId, clientSecret, } = await oauthClient.registerDevice(deviceId);

    const firstEvalResult = await this.evaluateAuth(flowId, deviceId, clientId, clientSecret);
    if (firstEvalResult.action === 'PASS') {
      const authorizationCode = await oauthClient.createAuthorizationCode(
        deviceId,
        clientId,
        clientSecret,
        firstEvalResult.oauth2CodeResponse.code
      );

      return this.createSessionFromAuthorizationCode(
        deviceId,
        clientId,
        clientSecret,
        authorizationCode
      );
    }

    const primaryChallenge = firstEvalResult.challenge.find(({ primary, }) => primary);
    if (!primaryChallenge) {
      throw new Error('No primary challenge found');
    }

    if (primaryChallenge.type !== EAuthChallengeType.PASSWORD) {
      debugger;
      throw new Error(`Primary challenge is not password: ${primaryChallenge.type}`);
    }

    const challengeResult = await this.submitPasswordChallenge(
      flowId,
      deviceId,
      clientId,
      clientSecret,
      firstEvalResult.authContextId
    );

    const secondEvalResult = await this.evaluateAuth(
      flowId,
      deviceId,
      clientId,
      clientSecret,
      challengeResult.oauth2CodeResponse.code
    );

    if (secondEvalResult.action !== 'PASS') {
      throw new Error('Second evaluation failed');
    }

    const authorizationCode = await oauthClient.createAuthorizationCode(
      deviceId,
      clientId,
      clientSecret,
      secondEvalResult.oauth2CodeResponse.code
    );

    return this.createSessionFromAuthorizationCode(
      deviceId,
      clientId,
      clientSecret,
      authorizationCode
    );
  }

  private createSessionFromAuthorizationCode(
    deviceId: string,
    clientId: string,
    clientSecret: string,
    authorizationCode: TOAuthAuthorizationCodeResponse
  ): TSession {
    const {
      access_token,
      refresh_token,
      x_refresh_token_expires_in,
    } = authorizationCode;

    return {
      deviceId,
      clientId,
      clientSecret,

      accessToken: access_token,
      refreshToken: refresh_token,
      refreshTokenExpiresAt: Date.now() + (x_refresh_token_expires_in * 1_000),
    };
  }

  private async revokeSession() {
    logger.info('Revoking session...');

    if (!this.session) { return; }

    const {
      deviceId,
      clientId,
      clientSecret,
      refreshToken,
    } = this.session;

    await oauthClient.revokeBearerToken(deviceId, clientId, clientSecret, refreshToken)
      .catch(() => logger.error('Failed to revoke session token'));

    this.session = undefined;

    this.sessionStore.set('auth', undefined);
  }

  private async evaluateAuth(
    flowId: string,
    deviceId: string,
    clientId: string,
    clientSecret: string,
    authCode?: string
    ) {
    const { access_token, } = authCode
      ? await oauthClient.createAuthorizationCode(deviceId, clientId, clientSecret, authCode)
      : await oauthClient.createClientCredentials(deviceId, clientId, clientSecret);

    logger.info(`Evaluating auth for ${this.username}...`);

    const payload = {
      oauth2CodeRequest: {
        clientId,
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
              value: EMagicValues.NAMESPACE_ID,
            },
            {
              key: 'identifierTypes',
              value: 'email,username',
            },
          ],
        },
      ],
    };

    const { data, } = await this.client.post<TEvaluateAuthResponse>(
      'v2/oauth2codes/evaluate_auth',
      payload,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          [EIntuitHeaderName.DEVICE_ID]: deviceId,
          [EIntuitHeaderName.FLOW_ID]: flowId,
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'sms_otp voice_otp email_otp totp password pwd_reset collect_password collect_recovery_phone collect_confirm_recovery_phone collect_recovery_email collect_recovery_email_or_phone post_auth_challenges consent_7216_ty18 username_reset select_account ar_oow_kba captcha care',
        },
      }
    );

    logger.info(`Evaluated auth for ${this.username}: ${data.action}`);

    return data;
  }

  private async submitPasswordChallenge(
    flowId: string,
    deviceId: string,
    clientId: string,
    clientSecret: string,
    authContextId: string
  ) {
    const result = await this.submitChallenge(
      flowId,
      deviceId,
      clientId,
      clientSecret,
      authContextId,
      EAuthChallengeType.PASSWORD,
      this.password
    )
      .catch(error => {
        const responseCode = error.response?.data?.responseCode;

        if (responseCode === 'INVALID_CREDENTIALS') {
          throw new Error('Invalid credentials');
        }

        throw new Error(`Failed to submit password challenge: ${responseCode}`);
      });

    return result;
  }

  private async submitChallenge(
    flowId: string,
    deviceId: string,
    clientId: string,
    clientSecret: string,
    authContextId: string,
    type: EAuthChallengeType,
    value: string
  ) {
    const { access_token, } = await oauthClient.createClientCredentials(deviceId, clientId, clientSecret);

    logger.info(`Submitting challenge for ${type}...`);

    const payload = {
      challengeToken: [
        { type, value, },
      ],
      oauth2CodeRequest: { clientId, redirectUri: EMagicValues.OAUTH_REDIRECT_URI, },
    };

    const { data, } = await this.client.post<TVerifySignInResponse>(
      'v2/oauth2codes/verify_sign_in_confirmation',
      payload,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          [EIntuitHeaderName.DEVICE_ID]: deviceId,
          [EIntuitHeaderName.AUTH_CONTEXT_ID]: authContextId,
          [EIntuitHeaderName.FLOW_ID]: flowId,
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'post_auth_challenges consent_7216_ty18 pwd_reset username_reset',
        },
      }
    );

    logger.info(`Submitted challenge for ${type}; risk level: ${data.riskLevel}, status: ${data.oauth2CodeResponse.error}`);

    return data;
  }

  private async requestOTPToken(
    flowId: string,
    deviceId: string,
    clientId: string,
    clientSecret: string,
    authContextId: string,
    type: EOTPAuthChallengeType
    ) {
    const { access_token, } = await oauthClient.createClientCredentials(deviceId, clientId, clientSecret);

    logger.info(`Requesting ${type} type OTP...`);

    const payload = {
      challengeToken: [
        { type, },
      ],
    };

    await this.client.post(
      'v2/oauth2codes/send_sign_in_confirmation',
      payload,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          [EIntuitHeaderName.DEVICE_ID]: deviceId,
          [EIntuitHeaderName.AUTH_CONTEXT_ID]: authContextId,
          [EIntuitHeaderName.FLOW_ID]: flowId,
        },
      }
    );
  }

  private hydrateSession() {
    logger.info('Hydrating from session store...');

    const authStore = this.sessionStore.get('auth');
    if (!authStore) { return; }

    const {
      deviceId,
      clientId,
      clientSecret,
      accessToken,
      refreshToken,
      refreshTokenExpiresAt,
    } = authStore;

    if (!deviceId || !clientId || !clientSecret || !accessToken || !refreshToken || !refreshTokenExpiresAt) {
      logger.info('One or more values are missing from auth store');

      return;
    }

    if (refreshTokenExpiresAt < Date.now()) {
      logger.info('Stored refresh token has expired');

      return;
    }

    return {
      deviceId,
      clientId,
      clientSecret,
      accessToken,
      refreshToken,
      refreshTokenExpiresAt,
    };
  }
}
