import { NextFunction, Request, Response } from 'express'
import { ZodSchema } from 'zod'
import { verifyAccessToken } from './cognito'
import { MissingTokenError } from './errors'

const bearerToken = (req: Request) => {
  const [scheme, token] = (req.headers.authorization || '').split(' ')

  return scheme?.toLowerCase() === 'bearer' && token ? token : undefined
}

/**
 * Requires `Authorization: Bearer <accessToken>`. On success the raw token and its verified
 * claims are available to route handlers as `res.locals.accessToken` and `res.locals.user`.
 */
export const isAuthed = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const accessToken = bearerToken(req)

    if (!accessToken) {
      throw new MissingTokenError()
    }

    res.locals.user = await verifyAccessToken(accessToken)
    res.locals.accessToken = accessToken

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
