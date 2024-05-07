import { NextFunction, Request, Response } from "express";
import { auth } from "express-oauth2-jwt-bearer";
import jwt from 'jsonwebtoken';
import User from "../models/user";

declare global {
  namespace Express {
    interface Request {
      userId: string;
      auth0Id: string;
    }
  }
}

//function get from oath oauth package connect to auth0 3.36.42
export const jwtCheck = auth({
    audience: process.env.AUTH0_AUDIENCE,
    issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
    tokenSigningAlg: 'RS256',
  });

//find user
export const jwtParse = async(
  req:Request, 
  res:Response, 
  next:NextFunction
) => {
  const {authorization} = req.headers;

  //Bearer sdjgnsdfjkg
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.sendStatus(401);
  }
  //Bearer sdjgnsdfjkg -> se lay phan sau
  const token = authorization.split(" ")[1];

  try {
    const decoded = jwt.decode(token) as jwt.JwtPayload;
    const auth0Id = decoded.sub;

    const user = await User.findOne({auth0Id});

    if(!user) {
      return res.sendStatus(401);
    }

    //2 bien sau ko thay doi
    req.auth0Id = auth0Id as string;
    req.userId = user._id.toString();
    next();
  }catch(error) {
    return res.sendStatus(401);
  }
};