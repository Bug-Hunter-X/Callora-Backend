import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { InternalServerError, UnauthorizedError } from '../errors/index.js';

interface AdminJwtPayload {
  role: string;
  [key: string]: unknown;
}

export function adminAuth(req: Request, res: Response, next: NextFunction): void {
  // Path 1: API key header
  const apiKey = req.header('x-admin-api-key');
  if (apiKey && apiKey === process.env.ADMIN_API_KEY) {
    res.locals.adminActor = 'admin-api-key';
    next();
    return;
  }

  // Path 2: Bearer JWT with admin role
  const authHeader = req.header('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const secret = process.env.JWT_SECRET;

    if (!secret) {
      next(new InternalServerError('JWT_SECRET not configured'));
      return;
    }

    try {
      const payload = jwt.verify(token, secret) as AdminJwtPayload;
      if (payload.role === 'admin') {
        res.locals.adminActor = (payload.sub as string) || (payload.email as string) || 'admin-jwt';
        next();
        return;
      }
    } catch {
      // Fall through to 401
    }
  }

  next(new UnauthorizedError('Unauthorized: admin access required'));
}
