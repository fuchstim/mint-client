import { ImapFlow, ImapFlowOptions, MailboxLockObject, FetchMessageObject } from 'imapflow';
import { parse as parseHtml } from 'node-html-parser';
import Logger from '@ftim/logger';
const logger = Logger.ns('MFAHelpers', 'Email');

// https:// imapflow.com/module-imapflow-ImapFlow.html#ImapFlow
export type TEmailHelperOptions = ImapFlowOptions & {
  inbox?: string;
};

export async function getEmailToken(options: TEmailHelperOptions) {
  logger.info('Getting email token...');

  const inbox = options.inbox || 'INBOX';
  options.logger = options.logger ?? false;

  const client = new ImapFlow(options);

  await client.connect();

  let lock: MailboxLockObject | null = null;
  try {
    lock = await client.getMailboxLock(inbox);

    const { message, code, } = await findCode(client);

    await markRead(client, message);

    logger.info('Email token retrieved');

    return code;
  } catch (e: unknown) {
    const error = e as Error;

    logger.error('Failed to get email token:', error.message);

    throw e;
  } finally {
    lock?.release();

    await client.logout();
  }
}

async function findCode(client: ImapFlow) {
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

  let result: { message: FetchMessageObject, code: string } | null = null;

  for await (const message of generator) {
    if (result) { continue; }

    const body = message.bodyParts?.get('text')?.toString() ?? '';

    const parsedBody = parseHtml(body);

    const [ code, ] = parsedBody
      .querySelectorAll('p')
      .map(p => p.structuredText.trim())
      .filter(p => p.match(/\d{6}/));

    if (!code) { continue; }

    result = { message, code, };
  }

  if (!result) {
    throw new Error('No code found');
  }

  return result;
}

async function markRead(client: ImapFlow, message: FetchMessageObject) {
  await client.messageFlagsAdd(
    [ message.seq, ],
    [ '\\Seen', ]
  );
}
