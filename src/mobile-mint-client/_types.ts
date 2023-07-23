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
