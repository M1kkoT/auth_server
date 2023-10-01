// Description: This file contains the functions for the user routes
// TODO: add function check, to check if the server is alive
// TODO: add function to get all users
// TODO: add function to get a user by id
// TODO: add function to create a user
// TODO: add function to update a user
// TODO: add function to delete a user
// TODO: add function to check if a token is valid

import jwt from 'jsonwebtoken';
import {Request, Response, NextFunction} from 'express';
import CustomError from '../../classes/CustomError';
import {OutputUser, User, UserId} from '../../interfaces/User';
import {validationResult} from 'express-validator';
import userModel from '../models/userModel';
import bcrypt from 'bcrypt';
import DBMessageResponse from '../../interfaces/DBMessageResponse';
import MessageResponse from '../../interfaces/MessageResponse';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';

const userPost = async (
  req: Request<{}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const messages = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      next(new CustomError(messages, 400));
      return;
    }

    const user = req.body;
    user.password = await bcrypt.hash(user.password, 12);

    const newUser = await userModel.create(user);
    const response: LoginMessageResponse = {
      token: 'empty',
      message: 'user created',
      user: {
        id: newUser._id,
        user_name: newUser.user_name,
        email: newUser.email,
      },
    };
    res.json(response);
  } catch (error) {
    console.log(error);
    next(new CustomError('User creation failed', 500));
  }
};

const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const users = await userModel.find().select('-password -role -__v');
    const response = {
      message: 'Users found',
      data: users,
    };
    res.json(response);
  } catch (error) {
    next(new CustomError('Users not found', 500));
  }
};

const userGet = async (
  req: Request<{id: string}, {}, {}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await userModel
      .findById(req.params.id)
      .select('-password -role -__v');

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    const response = {
      message: 'User found',
      data: user,
    };

    res.json(response);
  } catch (error) {
    next(new CustomError('User not found', 500));
  }
};
const checkToken = async (req: Request, res: Response, next: NextFunction) => {
  if (!res.locals.user) {
    next(new CustomError('token not valid', 403));
  } else {
    const user = await userModel
      .findById(res.locals.user.id)
      .select('-password -role -__v');

    if (!user) {
      next(new CustomError('token not valid', 403));
      return;
    }

    console.log('USER', user);
    if (!req.headers['authorization']) {
      throw new CustomError('token not valid', 403);
    }
    const message: LoginMessageResponse = {
      token: req.headers['authorization'],
      message: 'token valid',
      user: {id: user._id, user_name: user.user_name, email: user.email},
    };
    res.json(message);
  }
};
const userPut = async (
  req: Request<{}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const messages = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      next(new CustomError(messages, 400));
      return;
    }
    const header = jwt.verify(
      (req.headers['authorization'] as string).split(' ')[1],
      process.env.JWT_SECRET as string
    );
    const user = header as UserId;

    if (user.role !== 'admin') {
      const updatedUser = await userModel.findByIdAndUpdate(user.id, req.body, {
        new: true,
      });

      if (!updatedUser) {
        next(new CustomError('User not found', 404));
        return;
      }

      const response: LoginMessageResponse = {
        token: 'empty',
        message: 'user updated',
        user: {
          id: updatedUser.id,
          user_name: updatedUser.user_name,
          email: updatedUser.email,
        },
      };
      res.json(response);
    } else {
      const updatedUser = await userModel.findByIdAndUpdate(
        (req.body as User).id,
        req.body,
        {
          new: true,
        }
      );

      if (!updatedUser) {
        next(new CustomError('User not found', 404));
        return;
      }

      const response: LoginMessageResponse = {
        token: 'empty',
        message: 'user updated',
        user: {
          id: updatedUser.id,
          user_name: updatedUser.user_name,
          email: updatedUser.email,
        },
      };
      res.json(response);
    }
  } catch (error) {
    console.log(error);
    next(new CustomError('User creation failed', 500));
  }
};
const userDelete = async (
  req: Request<{}, {}, {id: string}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const messages = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(', ');
      next(new CustomError(messages, 400));
      return;
    }

    const header = jwt.verify(
      (req.headers['authorization'] as string).split(' ')[1],
      process.env.JWT_SECRET as string
    );
    const user = header as UserId;
    if (user.role !== 'admin') {
      const deleted = await userModel.findByIdAndDelete(user.id);
      if (!deleted) {
        next(new CustomError('User not found', 404));
        return;
      }
      const message: LoginMessageResponse = {
        token: res.locals.token as string,
        message: 'token valid',
        user: deleted,
      };
      res.json(message);
    } else {
      if (!req.body.id) {
        throw new CustomError('User not found', 404);
      }
      const deleted = await userModel.findByIdAndDelete(req.body.id);
      if (!deleted) {
        next(new CustomError('User not found', 404));
        return;
      }
      const message: LoginMessageResponse = {
        token: res.locals.token as string,
        message: 'token valid',
        user: deleted,
      };
      res.json(message);
    }
  } catch (error) {
    console.log(error);
    next(new CustomError('User creation failed', 500));
  }
};

export {userPost, userListGet, userGet, checkToken, userPut, userDelete};
