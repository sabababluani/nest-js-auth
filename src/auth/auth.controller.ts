import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpException,
  HttpStatus,
  Request
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { validate } from 'class-validator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() createUserDto: CreateAuthDto) {
    const errors = await validate(createUserDto);
    if (errors.length > 0) {
      throw new HttpException(
        { message: 'Validation failed', errors },
        HttpStatus.BAD_REQUEST,
      );
    }
    return this.authService.register(createUserDto);
  }

  @Roles(Role.USER, Role.ADMIN)
  @Public()
  @Post('login')
  loginUser(@Body() body: loginUserDto) {
    return this.authService.login(body);
  }

  @Roles(Role.ADMIN)
  @Public()
  @Post('login/admin')
  async loginAdmin(@Body() createUserDto: CreateUserDto) {
    return this.authService.loginAdmin(createUserDto);
  }

  @UseGuards(AuthGuard)
  @Post('logout')
  async logout(@Request() req: any) {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = req.user.id;

    if (!token) {
      throw new HttpException('No token provided', HttpStatus.BAD_REQUEST);
    }

    return this.authService.logout(token, userId);
  }
}
