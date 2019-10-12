import {Arg, Ctx, Field, Int, Mutation, Query, Resolver, UseMiddleware} from 'type-graphql';
import {compare, hash} from 'bcryptjs';
import {User} from "./entity/User";
import {ObjectType} from "type-graphql";
import {MyContext} from "./MyContext";
import {createAccessToken, createRefreshToken} from "./auth";
import {isAuth} from "./isAuth";
import {sendRefreshToken} from "./sendRefreshToken";
import {getConnection} from "typeorm";

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string
}

@Resolver()
export class UserResolver {
  @Query(() => String)
  hello() {
    return "hi!";
  }
  
  @Query(() => String)
  @UseMiddleware(isAuth)
  bye(
    @Ctx() {payload}: MyContext
  ) {
    return `Your user id is: ${payload!.userId}`;
  }
  
  @Query(() => [User])
  users() {
    return User.find();
  }
  
  @Mutation(() => Boolean)
  async register(
    @Arg('email') email: string,
    @Arg('password') password: string,
    @Arg('username') username: string,
  ) {
    const hashedPassword = await hash(password, 12);
    try {
      await User.insert({
        email,
        password: hashedPassword,
        username
      });
    } catch (err) {
      console.error("REGISTER: ", err);
      return false;
    }
    return true;
  }
  
  @Mutation(() => Boolean)
  async revokeRefreshTokensForUser(
    @Arg('userId', () => Int) userId: number
  ) {
    try {
      // Goes to user entity and increment the tokenVersion
      await getConnection().getRepository(User).increment({ id: userId }, 'tokenVersion', 1 );
      return true
    } catch (err) {
      console.error("TOKEN_VERSION_INCREMENT: ", err);
      return false;
    }
  }
  
  @Mutation(() => LoginResponse)
  async login(
    @Arg("email") email: string,
    @Arg("password") password: string,
    @Ctx() {res}: MyContext
  ): Promise<LoginResponse> {
    const user = await User.findOne({
      where: {
        email
      }
    });
    if (!user) {
      throw new Error("could not find user");
    }
    
    const valid = await compare(password, user.password);
    if (!valid) {
      throw new Error("bad password");
    }
    
    // login successfully
    sendRefreshToken(res, createRefreshToken(user));
    
    return {
      accessToken: createAccessToken(user)
    }
  }
}
