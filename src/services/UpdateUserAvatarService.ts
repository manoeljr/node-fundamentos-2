import {getRepository} from 'typeorm';
import User from '../models/User';
import path from 'path';

import AppError from '../errors/AppError';

import uploadConfig from '../config/Upload';
import fs from 'fs';


interface Request {
  user_id: string;
  avatarFileName: string;
}

class UpdateUserAvatarService {
  public async execute({ user_id, avatarFileName}: Request): Promise<User> {
    const usersRepository = getRepository(User);
    const user = await usersRepository.findOne(user_id);

    if (!user) {
      throw new AppError('Only authenticated users can change avatar.', 401);
    }


    if (user.avatar) { // Deletando o avatar antigo
      const userAvatarFilePath = path.join(uploadConfig.directory, user.avatar);
      const userAvatarFileExists =  await fs.promises.stat(userAvatarFilePath);

      if (userAvatarFileExists) {
        await fs.promises.unlink(userAvatarFilePath);
      }
    }

    user.avatar = avatarFileName;

    await usersRepository.save(user);
    return user;
  }
}

export default UpdateUserAvatarService;
