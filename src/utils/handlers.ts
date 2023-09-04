import { NextFunction, RequestHandler, Request, Response } from 'express'

export const wrapRequestHandler = <P>(func: RequestHandler<P>) => {
  return async (req: Request<P>, res: Response, next: NextFunction) => {
    try {
      await func(req, res, next)
    } catch (error) {
      console.log('run error wraper')
      next(error)
    }
  }
}
