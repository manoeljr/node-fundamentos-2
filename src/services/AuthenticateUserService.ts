import { getRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import User from '../models/User';

import authConfig from '../config/auth';

import AppError from '../errors/AppError';

import { sign } from 'jsonwebtoken';


interface Request {
  email: string;
  password: string;
}

class AuthenticateUserService {
  public async execute({ email, password }: Request): Promise<{ user: User, token: string}> {
    const usersRepository = getRepository(User);

    const user = await usersRepository.findOne({ where: {email} });

    if (!user) {
      throw new AppError('Incorrect email/passoword combination !', 401);
    }

    const passwordMatched = await compare(password, user.password);

    if (!passwordMatched) {
      throw new AppError('Incorrect email/passoword combination !', 401);
    }

    const { secret, expiresIn } = authConfig.jwt;
    //parametros na funcção sign({informações do usuario e permissões}, uma chave,
    //                           { subjet:id do usuario, expiresIn:quanto tempo o token vai durar}
    //                          )
    const token = sign({}, secret, {
      subject: user.id,
      expiresIn,
    });

    return {
      user,
      token,
    };

  }
}

export default AuthenticateUserService;
