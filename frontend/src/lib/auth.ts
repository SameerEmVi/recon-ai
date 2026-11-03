// The single local bearer token, kept in localStorage (this is a localhost
// single-user tool). The backend is the real gate; this just carries the token.
const KEY = "recon-ai-token";

export function getToken(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    localStorage.setItem(KEY, token.trim());
  } catch {
    /* ignore (private mode) */
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
