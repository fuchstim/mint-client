import { IOTPProvider } from '../otp-providers';

export type TAuthTokenFormat = {
  type: 'numeric',
  minLength: number,
  maxLength: number
};

export enum ERiskLevel {
  BYPASS = 'BYPASS',
  MED = 'MED',
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
  | ({ action: 'CHALLENGE', authContextId?: string, attributes: TAttribute[], challenge: TAuthChallenge[] } & Partial<TVerifySignInResponse>);

export type TSession = {
  deviceId: string,
  clientId: string,
  clientSecret: string,

  accessToken: string,
  refreshToken: string,
  refreshTokenExpiresAt: number,
};

export enum EOTPType {
  /** Captcha token OTP. See {@link OTPProviders.CaptchaOTPProvider} for example implementation */
  CAPTCHA_TOKEN = 'CAPTCHA_TOKEN',
  /** Time-based OTP. See {@link OTPProviders.TOTPProvider} for example implementation */
  TOTP = 'TOTP',
  /** SMS OTP */
  SMS_OTP = 'SMS_OTP',
  /** Email OTP. See {@link OTPProviders.EmailOTPProvider} for example implementation */
  EMAIL_OTP = 'EMAIL_OTP',
}

export type TOTPProviders = Partial<Record<EOTPType, IOTPProvider>>;
