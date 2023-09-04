import { HttpStatusCode } from '~/constants/enum'
import { USER_MESSAGES } from '~/constants/messages'

type ErrorType = Record<
  string,
  {
    msg: string
    [key: string]: any
  }
>
export class ErrorWithStatus {
  message: string
  status: number
  constructor({ message, status }: { message: string; status: number }) {
    this.message = message
    this.status = status
  }
}

export class EntityError extends ErrorWithStatus {
  errors: ErrorType
  constructor({ errors, message = USER_MESSAGES.VALIDATION_ERROR }: { errors: ErrorType; message?: string }) {
    super({ message, status: HttpStatusCode.UnprocessableEntity })
    this.errors = errors
    this.message = message
  }
}
