import { ImapFlow, ImapFlowOptions, FetchMessageObject } from 'imapflow';
import { parse as parseHtml } from 'node-html-parser';
import Logger from '@ftim/logger';
const logger = Logger.ns('OTPProvider', 'Email');

import sleep from '../../common/sleep';

import { IOTPProvider } from './_types';

type TCustomOptions = { inbox: string, maxAttempts: number, delayMs: number, };

// https:// imapflow.com/module-imapflow-ImapFlow.html#ImapFlow
export type TEmailOTPProviderOptions = ImapFlowOptions & Partial<TCustomOptions>;

export class EmailOTPProvider implements IOTPProvider {
  private options: TEmailOTPProviderOptions & TCustomOptions;

  constructor(options: TEmailOTPProviderOptions) {
    this.options = {
      inbox: 'INBOX',
      logger: false,
      maxAttempts: 10,
      delayMs: 1_000,
      ...options,
    };
  }

  async getCode(): Promise<string> {
    logger.info('Getting email token...');

    const client = new ImapFlow(this.options);

    await client.connect();

    const lock = await client.getMailboxLock(this.options.inbox);
    try {
      for (let attempt = 0; attempt < this.options.maxAttempts; attempt++) {
        logger.info(`Beginning attempt #${attempt + 1}...`);

        const code = await this.tryGetCode(client);
        if (code) { return code; }

        logger.info('Email token not found, retrying...');

        await sleep(Math.pow(2, attempt) * this.options.delayMs);
      }

      throw new Error('Failed to get email token');
    } catch (e: unknown) {
      const error = e as Error;

      logger.error('Failed to get email token:', error.message);

      throw e;
    } finally {
      lock.release();

      await client.logout();
    }
  }

  private async tryGetCode(client: ImapFlow): Promise<string | void> {
    const recentMessages = await this.fetchRecentEmails(client);

    logger.info(`Found ${recentMessages.length} recent emails`);

    for (const message of recentMessages) {
      const code = this.parseEmail(message);

      if (!code) { continue; }

      logger.info('Email token found');

      await this.markRead(client, message);

      return code;
    }
  }

  private async fetchRecentEmails(client: ImapFlow): Promise<FetchMessageObject[]> {
    const generator = client.fetch(
      {
        deleted: false,
        seen: false,
        from: 'do_not_reply@intuit.com',
        since: new Date(Date.now() - 1000 * 60 * 60),
      },
      {
        uid: true,
        threadId: true,
        bodyParts: [ 'TEXT', ],
      }
    );

    const messages: FetchMessageObject[] = [];

    for await (const message of generator) {
      messages.push(message);
    }

    return messages;
  }

  private parseEmail(message: FetchMessageObject): string | null {
    const body = message.bodyParts?.get('text')?.toString() ?? '';

    const parsedBody = parseHtml(body);

    const [ code, ] = parsedBody
      .querySelectorAll('p')
      .map(p => p.structuredText.trim())
      .filter(p => p.match(/\d{6}/));

    return code ?? null;
  }

  private async markRead(client: ImapFlow, message: FetchMessageObject) {
    await client.messageFlagsAdd(
      [ message.seq, ],
      [ '\\Seen', ]
    );
  }
}

