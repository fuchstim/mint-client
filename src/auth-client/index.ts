import axios from 'axios';
import { createHash, randomUUID, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import path from 'path';
import fs from 'fs';
import jsonwebtoken, { JwtPayload } from 'jsonwebtoken';
import Logger from '@ftim/logger';
const logger = Logger.ns('Auth');

import { EBaseUrl, EIntuitHeaderName, EMagicValues, ETokenGrantType, defaultHeaders } from './_constants';
import { EAuthChallengeType, TAuthorizationCache, TEvaluateAuthResponse, TOAuthAuthorizationCodeResponse, TOAuthClientCredentialsResponse, TVerifySignInResponse } from './_types';

export class AuthClient {
  private deviceId: string = randomUUID();

  private userIdentifier: string;
  private password: string;

  private authorizationCode?: TOAuthAuthorizationCodeResponse;

  constructor(userIdentifier: string, password: string) {
    this.userIdentifier = userIdentifier;
    this.password = password;
  }

  get authCacheFileName() {
    const authCacheIdentifier = createHash('sha256').update(this.userIdentifier + this.password).digest('hex');

    return path.resolve(`.auth-cache-${authCacheIdentifier}.json`);
  }

  get refreshTokenExpiresAt() {
    return this.authorizationCode?.refresh_token_expires_at ?? new Date(0);
  }

  get accessTokenExpiresAt() {
    if (!this.authorizationCode) {
      return new Date(0);
    }

    const decoded = jsonwebtoken.decode(this.authorizationCode.access_token) as JwtPayload;

    const expiresAt = decoded?.exp ?? 0;

    return new Date(expiresAt * 1_000);
  }

  async getAccessToken() {
    if (!this.authorizationCode || this.refreshTokenExpiresAt < new Date()) {
      this.authorizationCode = await this.authenticate();

      this.cacheAuthorizationCode();
    }

    if (this.accessTokenExpiresAt < new Date()) {
      this.authorizationCode = await this.refreshAuthorizationCode(this.authorizationCode.refresh_token)
        .catch(error => {
          logger.error('Failed to refresh authorization code', error);

          return this.authenticate();
        });

      this.cacheAuthorizationCode();
    }

    return this.authorizationCode.access_token;
  }

  private async authenticate() {
    logger.info('Authenticating...');

    const cachedAuthorizationCode = await this.getCachedAuthorizationCode();
    if (cachedAuthorizationCode) {
      return cachedAuthorizationCode;
    }

    const firstEvalResult = await this.evaluateAuth();
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

    const challengeResult = await this.submitPasswordChallenge(firstEvalResult.authContextId);

    const secondEvalResult = await this.evaluateAuth(challengeResult.oauth2CodeResponse.code);

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
    const data = await this.createBearerToken<Omit<TOAuthAuthorizationCodeResponse, 'refresh_token_expires_at'>, { code: string, redirect_uri: string }>({
      code,
      grant_type: ETokenGrantType.AUTHORIZATION_CODE,
      redirect_uri: EMagicValues.OAUTH_REDIRECT_URI,
    });

    return {
      ...data,
      refresh_token_expires_at: new Date(Date.now() + data.x_refresh_token_expires_in),
    };
  }

  private async refreshAuthorizationCode(refresh_token: string) {
    const data = await this.createBearerToken<Omit<TOAuthAuthorizationCodeResponse, 'refresh_token_expires_at'>, { refresh_token: string }>({
      refresh_token,
      grant_type: ETokenGrantType.REFRESH_TOKEN,
    });

    return {
      ...data,
      refresh_token_expires_at: new Date(Date.now() + data.x_refresh_token_expires_in),
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

  private async evaluateAuth(authCode?: string) {
    const { access_token, } = authCode ? await this.createAuthorizationCode(authCode) : await this.createClientCredentials();

    logger.info(`Evaluating auth for ${this.userIdentifier}...`);

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
              value: this.userIdentifier,
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

    logger.info(`Evaluated auth for ${this.userIdentifier}: ${data.action}`);

    return data;
  }

  private async submitPasswordChallenge(authContextId: string) {
    const result = await this.submitChallenge(authContextId, EAuthChallengeType.PASSWORD, this.password)
      .catch(error => {
        const responseCode = error.response?.data?.responseCode;

        if (responseCode === 'INVALID_CREDENTIALS') {
          throw new Error('Invalid credentials');
        }

        throw new Error(`Failed to submit password challenge: ${responseCode}`);
      });

    return result;
  }

  private async submitChallenge(authContextId: string, type: EAuthChallengeType, value: string) {
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
          [EIntuitHeaderName.ACCEPT_AUTH_CHALLENGE]: 'post_auth_challenges consent_7216_ty18 pwd_reset username_reset',
          [EIntuitHeaderName.FLOW_ID]: EMagicValues.OAUTH_FLOW_ID,
          [EIntuitHeaderName.RISK_PROFILING_DATA]: EMagicValues.RISK_PROFILING_DATA,
        },
      }
    );

    logger.info(`Submitted challenge for ${type}; risk level: ${data.riskLevel}, status: ${data.oauth2CodeResponse.error}`);

    return data;
  }

  private cacheAuthorizationCode() {
    if (!this.authorizationCode) {
      throw new Error('No authorization code');
    }

    const cacheData: TAuthorizationCache = {
      deviceId: this.deviceId,
      refreshToken: this.authorizationCode.refresh_token,
      refreshTokenExpiresAt: this.authorizationCode.refresh_token_expires_at.getTime(),
    };

    const iv = randomBytes(16);
    const key = createHash('sha256').update(this.password).digest('base64').slice(0, 32);
    const cipher = createCipheriv('aes-256-cbc', key, iv);

    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(cacheData)),
      cipher.final(),
    ]);

    fs.writeFileSync(this.authCacheFileName, `${iv.toString('hex')}:${encrypted.toString('hex')}`);
  }

  private async getCachedAuthorizationCode() {
    logger.info('Reading authorization cache...');

    try {
      const cacheFile = fs.readFileSync(this.authCacheFileName, 'utf8');

      const [ iv, encrypted, ] = cacheFile.split(':');
      const key = createHash('sha256').update(this.password).digest('base64').slice(0, 32);

      const decipher = createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encrypted, 'hex')),
        decipher.final(),
      ]);

      const cacheData = JSON.parse(decrypted.toString()) as TAuthorizationCache;

      if (!cacheData.deviceId || !cacheData.refreshToken || !cacheData.refreshTokenExpiresAt) {
        throw new Error('One or more values are missing');
      }

      if (cacheData.refreshTokenExpiresAt < Date.now()) {
        throw new Error('Cached refresh token has expired');
      }

      this.deviceId = cacheData.deviceId;

      logger.info('Validating cached credentials...');

      const authorizationCode = await this.refreshAuthorizationCode(cacheData.refreshToken);

      return authorizationCode;
    } catch (e) {
      const error = e as Error;
      logger.info(`No valid authorization cache found: ${error.message}`);

      return;
    }
  }
}
