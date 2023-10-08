import { BadRequestException, Inject, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, LoginDto, UpdateAuthDto, RegisterUserDto } from './dto';

import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,) { }


  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      // 1- Encriptar la contraseña

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData

      });

      await newUser.save();
      // const { password: _, ...user } = newUser.toJSON();

      return newUser.toJSON();
      // 2- Guardar el usuario

      // 3- Generar el JWT(json web token)

      // const newUser = new this.userModel(createUserDto);
      // return await newUser.save();

    } catch (error) {
      // console.log(error.code)
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException('Something terrible happen!!!')
    }
  }


  async register(registerUser: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUser);

    console.log({ user });

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    };

  }

  async login(loginDto: LoginDto) {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email');
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const { password: _, ...rest } = user.toJSON();


    return {
      user:rest,
      token: this.getJwtToken({ id: user._id }),
    };
    /**
     * User {_id,name,email,roles,}
     * Token -> ASDSADS.ASDASDASD.ASDASDASDASD
     **/

  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }


  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;

  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }

}
