export interface IOTPProvider {
  getCode(): string | Promise<string>;
}
