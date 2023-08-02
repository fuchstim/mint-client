import { URL } from 'url';

import express from 'express';
import Logger from '@ftim/logger';
const logger = Logger.ns('MFAHelpers', 'Captcha');

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

export type TCaptchaHelperOptions = {
  timeoutMs?: number;
  port?: number;
  host?: string;
};

type TCallbackParams = { accessToken: string, error: null } | { accessToken: null, error: Error };

function getCaptchaTokenCallback(callback: (params: TCallbackParams) => void, { timeoutMs = 60_000, port = 8080, host = 'localhost', }: TCaptchaHelperOptions) {
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

  const server = app.listen(port, host, () => {
    logger.info(`Captcha server listening at ${callbackHost}`);
  });
}

export function getCaptchaToken(options: TCaptchaHelperOptions = {}): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const callback = ({ accessToken, error, }: TCallbackParams) => {
      if (error) {
        reject(error);
      } else {
        resolve(accessToken);
      }
    };

    getCaptchaTokenCallback(callback, options);
  });
}
