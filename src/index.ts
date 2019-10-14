import 'dotenv/config';
import "reflect-metadata";
import express from 'express';
import {ApolloServer} from "apollo-server-express";
import {buildSchema} from "type-graphql";
import {createConnection} from "typeorm";
import cookieParser from 'cookie-parser';
import {verify} from "jsonwebtoken";
import cors from 'cors';
import {UserResolver} from "./resolvers/UserResolver";
import {User} from "./entity/User";
import {createAccessToken, createRefreshToken} from "./auth";
import {sendRefreshToken} from "./sendRefreshToken";


(async () => {
  const app = express();
  
  // CORS setup
  app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
  }));
  
  // It parses our cookies to the req of our routes
  app.use(cookieParser());
  
  // Express routes
  app.get('/', (_req, res) => res.send('hello'));
  
  app.post("/refresh_token", async (req, res) => {
    const token = req.cookies.jid;
    if (!token) {
      return res.send({ok: false, accessToken: '', message: 'NO_TOKEN'});
    }
    
    let payload: any;
    try {
      payload = verify(token, process.env.REFRESH_TOKEN_SECRET!);
    } catch (err) {
      console.error("Refreshing token: ", err);
      return res.send({ok: false, accessToken: '', message: 'INVALID_TOKEN'});
    }
    
    // We have a valid token
    const user = await User.findOne({ id: payload.userId });
    
    if (!user) {
      return res.send({ok: false, accessToken: '', message: 'NO_USER_FOUND'});
    }
    
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.send({ok: false, accessToken: '', message: 'MISMATCHING_TOKEN_VERSION'});
    }
    
    
    sendRefreshToken(res, createRefreshToken(user));
    
    return res.send({ok: true, accessToken: createAccessToken(user)});
  });
  
  try {
    await createConnection();
  } catch (e) {
    console.error("Create Connection: ", e);
  }
  
  const apolloServer = new ApolloServer({
    schema: await buildSchema({
      resolvers: [UserResolver]
    }),
    context: ({ req, res }) => ({ req, res })
  });
  
  apolloServer.applyMiddleware({ app, cors: false });
  
  app.listen(4000, () => {
    console.log("express server started");
  });
})();

// createConnection().then(async connection => {
//
//     console.log("Inserting a new user into the database...");
//     const user = new User();
//     user.firstName = "Timber";
//     user.lastName = "Saw";
//     user.age = 25;
//     await connection.manager.save(user);
//     console.log("Saved a new user with id: " + user.id);
//
//     console.log("Loading users from the database...");
//     const users = await connection.manager.find(User);
//     console.log("Loaded users: ", users);
//
//     console.log("Here you can setup and run express/koa/any other framework.");
//
// }).catch(error => console.log(error));
