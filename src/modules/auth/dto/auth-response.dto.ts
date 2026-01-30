export class AuthResponseDto {
  user: {
    id: string;
    email: string;
    isVerified: boolean;
    roles: string[];
  };
  accessToken: string;
}

export class SessionDto {
  id: string;
  deviceId?: string;
  deviceName?: string;
  ipAddress: string;
  lastUsedAt: Date;
  createdAt: Date;
  isCurrent: boolean;
}

export class SessionListDto {
  sessions: SessionDto[];
}