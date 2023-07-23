export type TOAuthClientCredentialsResponse = {
  token_type: 'bearer',

  access_token: string,
  expires_in: number,
};

export type TOAuthAuthorizationCodeResponse = TOAuthClientCredentialsResponse & {
  id_token: string,
  refresh_token: string,
  x_refresh_token_expires_in: number,
};

export type TAuthTokenFormat = {
  type: 'numeric',
  minLength: number,
  maxLength: number
};

export enum ERiskLevel {
  BYPASS = 'BYPASS',
  LOW = 'LOW'
}

export type TOAuthCodeResponse = {
  error: 'SUCCESS',
  code: string,
  userIdPseudonym: string,
};

export type TVerifySignInResponse = {
  riskLevel: ERiskLevel,
  oauth2CodeResponse: TOAuthCodeResponse,
};

export enum EAuthChallengeType {
  PASSWORD = 'PASSWORD',
  CARE = 'CARE',
  CAPTCHA = 'CAPTCHA',
  TOTP = 'TOTP',
  SMS_OTP = 'SMS_OTP',
  EMAIL_OTP = 'EMAIL_OTP',
}

export type TAuthChallenge = { primary: boolean, generated: boolean, } & (
  | { type: EAuthChallengeType.PASSWORD, }
  | { type: EAuthChallengeType.CARE, }
  | { type: EAuthChallengeType.CAPTCHA, }
  | { type: EAuthChallengeType.TOTP, tokenFormat: TAuthTokenFormat, }
  | { type: EAuthChallengeType.SMS_OTP, value: string, tokenFormat: TAuthTokenFormat }
  | { type: EAuthChallengeType.EMAIL_OTP, value: string, tokenFormat: TAuthTokenFormat }
);

export type TAttribute = { key: string, value: string };

export type TEvaluateAuthResponse =
  | ({ action: 'PASS', attributes: TAttribute[] } & TVerifySignInResponse)
  | { action: 'CHALLENGE', authContextId: string, attributes: TAttribute[], challenge: TAuthChallenge[] };
