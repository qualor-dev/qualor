export const endpoint = 'https://api.example.com';
const apiKey = "Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1";
export function authHeader(): string {
  return `Bearer ${apiKey}`;
}
