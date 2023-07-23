import { AuthClient } from './client/auth';

const authClient = new AuthClient('tim@shakepay.com', '-ba3DZk7dwbQq!_QeJJYshTckPKyLa*2');

authClient.getAccessToken().then(console.log);
