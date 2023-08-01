import fs from 'fs';
import prompts from 'prompts';

import SessionStore from './common/session-store';
import AuthClient from './auth';
import MobileMintClient from './mobile-mint-client';
import DataApiClient from './data-api-client';
import { EUserInputType } from './auth/access-platform-client';
import requestCaptchaToken from './auth/captcha-server';

const { username, password, } = JSON.parse(fs.readFileSync('./.test-credentials.json', 'utf-8'));

const sessionStore = new SessionStore({
  identifier: username + '3',
  secret: password,
});

const authClient = new AuthClient({
  sessionStore,
  username,
  password,
  userInputProvider: async type => {
    if (type === EUserInputType.CAPTCHA_TOKEN) {
      const captchaToken = await requestCaptchaToken();

      return captchaToken;
    }

    const { input, } = await prompts({ type: 'text', name: 'input', message: `Enter ${type}`, });

    return input;
  },
});

const mobileMintClient = new MobileMintClient({
  sessionStore,
  authClient,
});

const dataApiClient = new DataApiClient(authClient);

const run = async () => {
  // const budgetSummary = await dataApiClient.query(
  //   'getBudgetSummary',
  //   { date: new Date(), }
  // );

  // debugger;

  // const [ userProfile, categories, ] = await Promise.all([
  //   ,
  //   mobileMintClient.getCategories(),
  // ]);

  const userProfile = await mobileMintClient.getUserProfile();
  const accountIds = userProfile.accounts.map(a => a.accountId);

  const transactions = await mobileMintClient.getTransactions(
    accountIds,
    new Date(0),
    new Date(),
    100
  );

  debugger;

  // fs.writeFileSync(
  //   'transactions.json',
  //   JSON.stringify(transactions, null, 2)
  // );
};

run();

