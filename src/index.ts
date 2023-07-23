import fs from 'fs';

import { SessionStore } from './common/session-store';
import { AuthClient } from './auth-client';
import { MobileMintClient } from './mobile-mint-client';

const { username, password, } = JSON.parse(fs.readFileSync('./.test-credentials.json', 'utf-8'));

const sessionStore = new SessionStore(username, password);

const authClient = new AuthClient(sessionStore, username, password);

authClient.getAccessToken().then(console.log);

// const mobileMintClient = new MobileMintClient(authClient);

// mobileMintClient.init().then(console.log);
