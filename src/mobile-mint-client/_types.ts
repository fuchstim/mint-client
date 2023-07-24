import { UUID } from 'crypto';

export type TGetNewUuidResponse = {
  uuid: UUID
};

export type TRegisterDeviceIdResponse = {
  versionValidity: string,
  entitlements: string,
  responseType: string,
  mpxvErrorId: string,
  protocolValidity: string,
  guid: string,
  mintPN: string,
  currentProtocol: string,
  userId: number,
  currentVersion: string,
  token: string,
};

export type TCategory = {
  id: number,
  categoryType: string,
  depth: number,
  categoryName: string,
  notificationName: string,
  parentId: number,
  precedence: number,
  standard: boolean,
  modified: number,
  isBusiness: boolean,
  categoryFamily: string
};

export type TProcessRequestType<K extends string, P extends object, R extends object> = {
  responseKey: K,
  payload: P,
  response: R
};

export type TProcessRequestTypes = {
  getCategories: TProcessRequestType<
    'categoriesResponse',
    { includeDeletedCategories: boolean, modifiedFrom: string },
    { entries: TCategory[] }
  >
};
