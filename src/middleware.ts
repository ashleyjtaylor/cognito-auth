import { NextFunction, Request, Response } from 'express'
import { ZodSchema } from 'zod'
import { verifyToken } from './cognito'

export const isAuthed = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    await verifyToken(req.body.accessToken)
    next()
  } catch (error) {
    next(error)
  }
}

export const isValidRequest = (schema: ZodSchema) => (req: Request, _res: Response, next: NextFunction) => {
  try {
    schema.parse({
      body: req.body
    })

    next()
  } catch (error) {
    next(error)
  }
}
