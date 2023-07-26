import { UUID, randomUUID } from 'crypto';

import Logger from '@ftim/logger';
const logger = Logger.ns('Lock');

const ACTIVE_LOCKS: Record<string, { id: UUID, expiresAt: Date }> = {};

const isLockActive = (name: string) => {
  if (!ACTIVE_LOCKS[name]) { return false; }

  if (Date.now() > ACTIVE_LOCKS[name].expiresAt.getTime()) {
    return false;
  }

  return true;
};

export default class Lock {
  private name: string;

  constructor(name: string) {
    this.name = name;
  }

  async acquire(durationMs = 5_000, timeoutMs = 600_000) {
    const lockId = randomUUID();
    const lockLogger = logger.ns(this.name, lockId);

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        clearInterval(interval);

        lockLogger.error(`Failed to acquire lock within ${timeoutMs}ms`);

        reject(new Error(`Failed to acquire lock ${this.name} within ${timeoutMs}ms`));
      }, timeoutMs);

      const interval = setInterval(() => {
        if (isLockActive(this.name)) { return; }

        ACTIVE_LOCKS[this.name] = {
          id: lockId,
          expiresAt: new Date(Date.now() + durationMs),
        };

        clearInterval(interval);
        clearTimeout(timeout);

        resolve();
      }, 100);

    });

    return {
      id: lockId,
      release: () => {
        if (ACTIVE_LOCKS[this.name]?.id === lockId) {
          delete ACTIVE_LOCKS[this.name];
        }
      },
      renew: () => {
        if (ACTIVE_LOCKS[this.name]?.id === lockId) {
          ACTIVE_LOCKS[this.name].expiresAt = new Date(Date.now() + durationMs);
        }
      },
    };
  }

  async runWithLock<R>(fn: () => R): Promise<R> {
    const lock = await this.acquire();
    const renewalInterval = setInterval(() => lock.renew(), 1_000);

    try {
      const result = await fn.apply(fn, []);

      return result;
    } finally {
      clearInterval(renewalInterval);
      lock.release();
    }
  }
}
