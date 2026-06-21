// Casdoor session helpers: a tiny cookie jar + bootstrap login/signup.
//
// Enrolling a passkey (WebAuthnSignupBegin/Finish) requires an authenticated
// Casdoor session for the target user — getCurrentUser() reads the session
// cookie. This is the one-time bootstrap: an invited user signs up with the
// invitation code (the one-time secret), or an existing user logs in with a
// password. From then on login is passwordless via the passkey.

export interface CookieJar {
  absorb(response: Response): void;
  header(): string;
  readonly size: number;
}

/** Parse Set-Cookie headers into a "name=value; name=value" Cookie string. */
export function makeCookieJar(): CookieJar {
  const jar = new Map<string, string>();
  return {
    absorb(response: Response): void {
      const setCookies =
        typeof response.headers.getSetCookie === 'function'
          ? response.headers.getSetCookie()
          : [response.headers.get('set-cookie')].filter((v): v is string => Boolean(v));
      for (const sc of setCookies) {
        const first = sc.split(';')[0] ?? '';
        const eq = first.indexOf('=');
        if (eq > 0) jar.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
      }
    },
    header(): string {
      return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    },
    get size(): number {
      return jar.size;
    },
  };
}

/** Build a Cookie header directly from one response's Set-Cookie(s). */
export function cookieHeaderFrom(response: Response): string {
  const setCookies =
    typeof response.headers.getSetCookie === 'function'
      ? response.headers.getSetCookie()
      : [response.headers.get('set-cookie')].filter((v): v is string => Boolean(v));
  return setCookies.map((sc) => sc.split(';')[0]).join('; ');
}

/** Password-login to Casdoor and return a cookie jar carrying the session. */
export async function passwordLogin(o: {
  host: string;
  organization: string;
  username: string;
  password: string;
  application: string;
}): Promise<CookieJar> {
  const jar = makeCookieJar();
  const res = await fetch(`${o.host}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'login',
      application: o.application,
      organization: o.organization,
      username: o.username,
      password: o.password,
      autoSignin: true,
    }),
  });
  const body = (await res.json().catch(() => ({}))) as { status?: string; msg?: string };
  if (body.status !== 'ok') {
    throw new Error(`Casdoor login failed: ${body.msg || JSON.stringify(body).slice(0, 200)}`);
  }
  jar.absorb(res);
  if (jar.size === 0) throw new Error('Casdoor login returned no session cookie');
  return jar;
}

/**
 * Sign up a new user via an invitation code and return the session cookie jar.
 * The invitation code is the one-time secret (no human password); Casdoor's
 * /api/signup creates the user and establishes a session, so the jar can be used
 * directly for WebAuthnSignupBegin/Finish. The `password` is throwaway (the code).
 */
export async function signupWithInvitation(o: {
  host: string;
  organization: string;
  application: string;
  username: string;
  password: string;
  name?: string;
  invitationCode: string;
}): Promise<CookieJar> {
  const jar = makeCookieJar();
  const res = await fetch(`${o.host}/api/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      application: o.application,
      organization: o.organization,
      username: o.username,
      password: o.password,
      name: o.name || o.username,
      invitationCode: o.invitationCode,
      autoSignin: true,
    }),
  });
  const body = (await res.json().catch(() => ({}))) as { status?: string; msg?: string };
  if (body.status !== 'ok') {
    throw new Error(`Casdoor signup failed: ${body.msg || JSON.stringify(body).slice(0, 200)}`);
  }
  jar.absorb(res);
  if (jar.size === 0) throw new Error('Casdoor signup returned no session cookie');
  return jar;
}
