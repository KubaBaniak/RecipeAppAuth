import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Strategies } from '../constants';

@Injectable()
export class LocalAuthGuard extends AuthGuard(Strategies.Local) {}
