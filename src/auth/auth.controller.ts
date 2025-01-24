import {Body, Controller, Inject, Post} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Prisma } from '@prisma/client';

@Controller('auth')
export class AuthController {

    @Inject()
    private readonly authService: AuthService;

    @Post('signin')
    signin(@Body() body: Prisma.UserCreateInput) {
        return this.authService.signin(body);
    }
}
