import 'express-session';

export interface UserSessionData {
  id: number;
  username: string;
  role: 'customer' | 'admin';
  email: string;
  fullName: string;
}

declare module 'express-session' {
  interface SessionData {
    user?: UserSessionData;
  }
}
