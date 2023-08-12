import { URL } from 'url';

import express from 'express';
import Logger from '@ftim/logger';
import { IOTPProvider } from './_types';
const logger = Logger.ns('OTPProvider', 'Captcha');

const indexHtml = /* html */`
<html>

<head>
  <style type="text/css">
    html,
    body {
      margin: 0;
      padding: 0;
      width: 100%;
      height: 100%;
    }

    iframe {
      width: 100%;
      height: 100%;
      border: none;
    }
  </style>

  <script type="text/javascript">
    function parseAccessToken() {
      const iframe = document.getElementById('captchaFrame');

      console.log(iframe)
    }
  </script>
</head>

<body>
  <iframe id="captchaFrame" onload="parseAccessToken()" src="{{captchaUrl}}" />
</body>

</html>
`;

export type TCaptchaOTPProviderOptions = {
  timeoutMs?: number;
  port?: number;
  host?: string;
};

type TCallbackParams = { accessToken: string, error: null } | { accessToken: null, error: Error };

/**
 * Spins up a lightweight express server to serve the captcha and intercept the response. `captcha_token` included in intercepted response functions as OTP.
 *
 * To obtain `captcha_token` manually, first assemble the url to access the captcha page.
 * The base URL is `https://accounts.intuit.com/recaptcha-native.html`, and requires the following query-string parameters:
 * * `offering_id`: should equal `Intuit.ifs.mint.3`
 * * `locale`: should equal `en-ca`
 * * `redirect_url`:  after solving the captcha, the user will be redirected to this URL (including the `captcha_token` query-string param). My testing indicated the protocol, hostname, or port of this URL are not validated, however the path needs to be exactly `/nativeredirect/v1`
 *
 * A valid captcha page URL might be: `https://accounts.intuit.com/recaptcha-native.html?offering_id=Intuit.ifs.mint.3&locale=en-ca&redirect_url=https://example.com/nativeredirect/v1`. On successful completion, the user would be redirected to `https://example.com/nativeredirect/v1?captcha_token=<the token we need>`
 *
 * @example
 * ```typescript
 * new OTPProviders.CaptchaOTPProvider({
 *  timeoutMs: 60_000,
 *  port: 8080,
 *  host: 'localhost',
 * });
 * ```
 */
export class CaptchaOTPProvider implements IOTPProvider {
  private timeoutMs: number;
  private port: number;
  private host: string;

  constructor(options: TCaptchaOTPProviderOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.port = options.port ?? 8080;
    this.host = options.host ?? 'localhost';
  }

  private get callbackHost() {
    return `http://${this.host}:${this.port}`;
  }

  async getCode(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const callback = ({ accessToken, error, }: TCallbackParams) => error ? reject(error) : resolve(accessToken);

      this.getCaptchaTokenCallback(callback);
    });
  }

  private getCaptchaTokenCallback(callback: (params: TCallbackParams) => void) {
    const app = express();

    const captchaUrl = new URL('https://accounts.intuit.com/recaptcha-native.html');
    captchaUrl.searchParams.append('offering_id', 'Intuit.ifs.mint.3');
    captchaUrl.searchParams.append('locale', 'en-ca');
    captchaUrl.searchParams.append('redirect_url', `${this.callbackHost}/nativeredirect/v1`);

    const timeout = setTimeout(
      () => onError(new Error('Captcha request timed out')),
      this.timeoutMs
    );

    const onSuccess = (accessToken: string) => {
      logger.info('Captcha token received');

      server.close();
      clearTimeout(timeout);

      callback({ accessToken, error: null, });
    };

    const onError = (error: Error) => {
      logger.error('Failed to receive captcha token:', error.message);

      server.close();
      clearTimeout(timeout);

      callback({ accessToken: null, error, });
    };

    app.get('/nativeredirect/v1', (req, res) => {
      const { captcha_token, } = req.query;

      res.send('OK');

      if (captcha_token) {
        return onSuccess(captcha_token as string);
      }

      return onError(new Error('Invalid callback received'));
    });

    app.get('/*', (req, res) => {
      res.send(indexHtml.replaceAll('{{captchaUrl}}', captchaUrl.href));
    });

    logger.info('Starting server...');

    const server = app.listen(this.port, this.host, () => {
      logger.info(`Captcha server listening at ${this.callbackHost}`);
    });
  }
}
