import { Response } from "express";

export const sendRefreshToken = (res: Response, token: string) => {
  res.cookie("jid", token, {
    httpOnly: true,
    // TODO: Create constants for paths
    path: "/refresh_token"
  });
};
