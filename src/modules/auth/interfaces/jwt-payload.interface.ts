export interface JwtPayload {
  sub: string;      // User ID
  email: string;
  roles: string[];
  iat?: number;    // Issued at
  exp?: number;
}

export interface JwtPayloadWithRefresh extends JwtPayload {
  refreshTokenId: string;
}