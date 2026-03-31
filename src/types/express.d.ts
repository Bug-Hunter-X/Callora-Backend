declare global {
  namespace Express {
    interface Request {
      id: string;
      user?: Record<string, unknown>;
      vault?: Record<string, unknown> | null;
      api?: Record<string, unknown>;
      endpoint?: Record<string, unknown>;
      apiKeyRecord?: Record<string, unknown>;
      apiKeyValue?: string;
    }
  }
}

export {};
