import path from 'path';
import fs from 'fs';

import Logger from '@ftim/logger';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';
const logger = Logger.ns('SessionStore');

export type TSessionStore = {
  auth?: {
    deviceId: string,
    refreshToken: string,
    refreshTokenExpiresAt: number,
  }
};

export class SessionStore {
  private identifier: string;
  private secret: string;

  private store: TSessionStore;

  constructor(identifier: string, secret: string) {
    this.identifier = identifier;
    this.secret = secret;

    try {
      this.store = this.readStore();
    } catch (e) {
      const error = e as Error;
      logger.error(`Failed to read session store: ${error.message}`);

      this.store = {};
    }
  }

  private get storeFileName() {
    const storeIdentifier = createHash('sha256').update(this.identifier).digest('hex');

    return path.resolve(`.session-store-${storeIdentifier}.json`);
  }

  private get encryptionKey() {
    return createHash('sha256').update(this.secret).digest('base64').slice(0, 32);
  }

  set<K extends keyof TSessionStore>(key: K, value: TSessionStore[K]) {
    this.store[key] = value;

    this.saveStore();
  }

  get<K extends keyof TSessionStore>(key: K): TSessionStore[K] {
    return this.store[key];
  }

  private readStore() {
    const storeFile = fs.readFileSync(this.storeFileName, 'utf8');

    const [ iv, encrypted, ] = storeFile.split(':');

    const decipher = createDecipheriv('aes-256-cbc', this.encryptionKey, Buffer.from(iv, 'hex'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'hex')),
      decipher.final(),
    ]);

    const store = JSON.parse(decrypted.toString()) as TSessionStore;

    return store;
  }

  private saveStore() {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-cbc', this.encryptionKey, iv);

    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(this.store)),
      cipher.final(),
    ]);

    fs.writeFileSync(this.storeFileName, `${iv.toString('hex')}:${encrypted.toString('hex')}`);
  }
}
