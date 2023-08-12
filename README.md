<br />

<div align="center">
  <a href="https://github.com/fuchstim/mint-client">
    <img src="https://raw.githubusercontent.com/fuchstim/mint-client/main/images/logotype.png" alt="Logo" width="400" height="80">
  </a>

  <p align="center">
    mint-client is an <b>unofficial</b> TypeScript library facilitating authentication and requests to the Intuit Mint platform
    <br />
    <a href="https://fuchstim.github.io/mint-client/classes/MintClient.html" target="_blank"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/fuchstim/mint-client/issues">Report Bug</a>
    ·
    <a href="https://github.com/fuchstim/mint-client/issues">Request Feature</a>
  </p>
</div>

## Installation

To install the mint-client library, run `npm install --save @ftim/mint-client`

## Usage

**Example:**

```typescript
import MintClient, { EOTPType, OTPProviders } from '@ftim/mint-client';

const client = new MintClient({
  username: 'supersaver',
  password: 'supersecurepassword',
  otpProviders: {
    [EOTPType.CAPTCHA_TOKEN]: new OTPProviders.CaptchaOTPProvider(),
    [EOTPType.TOTP]: new OTPProviders.TOTPProvider('TOTPSECRET'),
    [EOTPType.EMAIL_OTP]: new OTPProviders.EmailOTPProvider({
      host: 'imap.gmail.com',
      port: 993,
      auth: {
        user: 'supersaver@gmail.com',
        pass: 'supersecurepassword',
      },
    }),
  },
});
```

See [here](https://fuchstim.github.io/mint-client/classes/MintClient.html) for all available client methods.

## Roadmap

- [x] Generalize OTPProvider Interface
- [x] Implement retrieving history data (net worth, spending)
- [x] Implement retrieving budget statistics
- [ ] Implement logout method
