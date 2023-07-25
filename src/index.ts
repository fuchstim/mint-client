import fs from 'fs';

import { SessionStore } from './common/session-store';
import { AuthClient } from './auth-client';
import { MobileMintClient } from './mobile-mint-client';

const { username, password, } = JSON.parse(fs.readFileSync('./.test-credentials.json', 'utf-8'));

const sessionStore = new SessionStore({
  identifier: username + '1',
  secret: password,
});

const authClient = new AuthClient({
  sessionStore,
  username,
  password,
});

const mobileMintClient = new MobileMintClient({
  sessionStore,
  authClient,
});

mobileMintClient.getTransactions()
  .then(result => { debugger; })
  .catch(error => { debugger; });
