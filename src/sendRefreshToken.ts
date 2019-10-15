import { Response } from "express";

const REFRESH_TOKEN_PATH = "/refresh_token";

export const sendRefreshToken = (res: Response, token: string) => {
  res.cookie("jid", token, {
    httpOnly: true,
    path: REFRESH_TOKEN_PATH
  });
};

export const removeRefreshToken = (res: Response) => {
  res.clearCookie("jid", {
    path: REFRESH_TOKEN_PATH
  })
};
