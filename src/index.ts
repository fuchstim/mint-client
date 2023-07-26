import fs from 'fs';
import prompts from 'prompts';

import SessionStore from './common/session-store';
import AuthClient from './auth';
import MobileMintClient from './mobile-mint-client';

const { username, password, } = JSON.parse(fs.readFileSync('./.test-credentials.json', 'utf-8'));

const sessionStore = new SessionStore({
  identifier: username + '1',
  secret: password,
});

const authClient = new AuthClient({
  sessionStore,
  username,
  password,
  userInputProvider: async type => {
    const { input, } = await prompts({ type: 'text', name: 'input', message: `Enter ${type}`, });

    return input;
  },
});

const mobileMintClient = new MobileMintClient({
  sessionStore,
  authClient,
});

const run = async () => {
  const [ userProfile, categories, ] = await Promise.all([
    mobileMintClient.getUserProfile(),
    mobileMintClient.getCategories(),
  ]);

  const accountIds = userProfile.accounts.map(a => a.accountId);

  const transactions = await mobileMintClient.getTransactions(
    accountIds,
    new Date(0),
    new Date(),
    2000
  );

  fs.writeFileSync(
    'transactions.json',
    JSON.stringify(transactions, null, 2)
  );
};

run();

