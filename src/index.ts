import { AuthClient } from './client/auth';

const authClient = new AuthClient();

authClient.authenticate('tim@shakepay.com', '-ba3DZk7dwbQq!_QeJJYshTckPKyLa*2').then(console.log);
