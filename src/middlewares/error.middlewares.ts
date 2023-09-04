import { NextFunction, Request, Response } from 'express'
import { omit } from 'lodash'
import { HttpStatusCode } from '~/constants/enum'
import { ErrorWithStatus } from '~/models/Errors'

export const defaultErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof ErrorWithStatus) {
    return res.status(err.status).json(omit(err, ['status']))
  }
  Object.getOwnPropertyNames(err).forEach((key) => {
    Object.defineProperty(err, key, {
      enumerable: true
    })
  })
  return res.status(HttpStatusCode.InternalServerError).json({
    message: err.message
  })
}