export type TOAuthRegisterDeviceResponse = {
  client_id: string,
  client_secret: string,
};

export type TOAuthClientCredentialsResponse = {
  token_type: 'bearer',

  access_token: string,
  expires_in: number,
};

export type TOAuthAuthorizationCodeResponse = TOAuthClientCredentialsResponse & {
  id_token: string,
  refresh_token: string,
  x_refresh_token_expires_in: number,
};
