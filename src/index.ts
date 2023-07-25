import fs from 'fs';
import prompts from 'prompts';

import { SessionStore } from './common/session-store';
import { AccessPlatformClient } from './access-platform-client';
import { MobileMintClient } from './mobile-mint-client';

const { username, password, } = JSON.parse(fs.readFileSync('./.test-credentials.json', 'utf-8'));

const sessionStore = new SessionStore({
  identifier: username + '1',
  secret: password,
});

const accessPlatformClient = new AccessPlatformClient({
  sessionStore,
  username,
  password,
  otpProvider: async type => {
    const { token, } = await prompts([
      {
        type: 'text',
        name: 'token',
        message: `Enter ${type} token`,
      },
    ]);

    return token;
  },
});

const mobileMintClient = new MobileMintClient({
  sessionStore,
  accessPlatformClient,
});

mobileMintClient.getTransactions()
  .then(result => { debugger; })
  .catch(error => { debugger; });
