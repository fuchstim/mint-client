import fs from 'fs';

import { AuthClient } from './auth-client';

const { username, password, } = JSON.parse(fs.readFileSync('./.test-credentials.json', 'utf-8'));

const authClient = new AuthClient(username, password);

authClient.getAccessToken().then(console.log);
