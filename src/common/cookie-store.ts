import { AxiosResponse, InternalAxiosRequestConfig } from 'axios';

export class CookieStore {
  private cookies: Record<string, string>;

  constructor(initialCookies?: Record<string, string>) {
    this.cookies = initialCookies ?? {};
  }

  get requestInterceptor() {
    return (request: InternalAxiosRequestConfig) => {
      const cookieHeader = Object.entries(this.cookies)
        .map(([ key, value, ]) => `${key}=${value}`)
        .join('; ');

      request.headers.set('Cookie', cookieHeader);

      return request;
    };
  }

  get responseInterceptor() {
    return (response: AxiosResponse) => {
      const cookieHeaders = response.headers['set-cookie'] ?? [];

      const updatedCookies = cookieHeaders.reduce(
        (acc, header) => {
          const [ keyValue, ] = header.split(';');

          const separatorIndex = keyValue.indexOf('=');
          if (separatorIndex === -1) { return acc; }

          const key = keyValue.slice(0, separatorIndex);
          const value = keyValue.slice(separatorIndex + 1);

          return { ...acc, [key]: value, };
        },
        {} as Record<string, string>
      );

      this.cookies = {
        ...this.cookies,
        ...updatedCookies,
      };

      return response;
    };
  }

  getCookies() {
    return { ...this.cookies, };
  }

  setCookies(cookies: Record<string, string>) {
    this.cookies = cookies;
  }

  reset() {
    this.cookies = {};
  }
}