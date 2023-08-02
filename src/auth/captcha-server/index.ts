import path from 'path';
import fs from 'fs';
import { URL } from 'url';

import express from 'express';
import Logger from '@ftim/logger';
const logger = Logger.ns('CaptchaServer');

const indexPath = path.join(__dirname, 'index.html');
const indexFile = fs.readFileSync(indexPath, 'utf-8').toString();

export type TCaptchaServerOptions = {
  timeoutMs?: number;
  port?: number;
  host?: string;
};

type TCallbackParams = { accessToken: string, error: null } | { accessToken: null, error: Error };

function requestCaptchaTokenCallback(callback: (params: TCallbackParams) => void, { timeoutMs = 60_000, port = 8080, host = 'localhost', }: TCaptchaServerOptions) {
  const app = express();
  const callbackHost = `http://${host}:${port}`;

  const captchaUrl = new URL('https://accounts.intuit.com/recaptcha-native.html');
  captchaUrl.searchParams.append('offering_id', 'Intuit.ifs.mint.3');
  captchaUrl.searchParams.append('locale', 'en-ca');
  captchaUrl.searchParams.append('redirect_url', `${callbackHost}/nativeredirect/v1`);

  const timeout = setTimeout(
    () => onError(new Error('Captcha request timed out')),
    timeoutMs
  );

  const onSuccess = (accessToken: string) => {
    server.close();
    clearTimeout(timeout);

    callback({ accessToken, error: null, });
  };

  const onError = (error: Error) => {
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
    res.send(indexFile.replaceAll('{{captchaUrl}}', captchaUrl.href));
  });

  const server = app.listen(port, host, () => {
    logger.info(`Captcha server listening at ${callbackHost}`);
  });
}

export default function requestCaptchaToken(options: TCaptchaServerOptions = {}) {
  return new Promise<string>((resolve, reject) => {
    const callback = ({ accessToken, error, }: TCallbackParams) => {
      if (error) {
        reject(error);
      } else {
        resolve(accessToken);
      }
    };

    requestCaptchaTokenCallback(callback, options);
  });
}
