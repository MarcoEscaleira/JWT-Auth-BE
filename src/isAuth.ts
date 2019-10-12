import {MiddlewareFn} from "type-graphql";
import {MyContext} from "./MyContext";
import {verify} from "jsonwebtoken";

export const isAuth: MiddlewareFn<MyContext>  = ({ context }, next) => {
  const authorization = context.req.headers['authorization'];
  
  if (!authorization) {
    throw new Error("not authenticated");
  }
  
  try {
    const token = authorization.split(" ")[1];
    const payload = verify(token, process.env.ACCESS_TOKEN_SECRET!);
    
    context.payload = payload as any;
  } catch (err) {
    console.error("is Auth: ", err);
  }
  
  return next();
};
