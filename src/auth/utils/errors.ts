import { RpcException } from '@nestjs/microservices';

export class BadRequestRpcException extends RpcException {
  constructor(overrideMessage?: string) {
    const defaultErrorMessage = 'Bad request';
    const status = 400;
    const message = overrideMessage || defaultErrorMessage;

    super({ message, status });
  }
}

export class UnauthorizedRpcException extends RpcException {
  constructor(overrideMessage?: string) {
    const defaultErrorMessage = 'Unauthorized';
    const status = 401;
    const message = overrideMessage || defaultErrorMessage;

    super({ message, status });
  }
}

export class ForbiddenRpcException extends RpcException {
  constructor(overrideMessage?: string) {
    const defaultErrorMessage = 'Forbidden';
    const status = 403;
    const message = overrideMessage || defaultErrorMessage;

    super({ message, status });
  }
}

export class NotFoundRpcException extends RpcException {
  constructor(overrideMessage?: string) {
    const defaultErrorMessage = 'Not found';
    const status = 404;
    const message = overrideMessage || defaultErrorMessage;

    super({ message, status });
  }
}
