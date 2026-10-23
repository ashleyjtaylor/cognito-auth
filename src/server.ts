import express, { NextFunction, Request, Response } from 'express'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { ZodError } from 'zod'
import { FetchError, JwksNotAvailableInCacheError, JwtBaseError, JwtExpiredError } from 'aws-jwt-verify/error'
import {
  CodeMismatchException,
  ExpiredCodeException,
  InvalidParameterException,
  InvalidPasswordException,
  LimitExceededException,
  NotAuthorizedException,
  PasswordResetRequiredException,
  TooManyFailedAttemptsException,
  TooManyRequestsException,
  UserNotConfirmedException,
  UserNotFoundException,
  UsernameExistsException
} from '@aws-sdk/client-cognito-identity-provider'

import { config } from './config'
import { InvalidTokenError, MissingTokenError } from './errors'
import { isAuthed, isValidRequest } from './middleware'

import {
  login,
  respondToChallenge,
  signup,
  confirmSignup,
  forgotPassword,
  confirmForgotPassword,
  resendSignupConfirmationCode,
  refreshToken,
  logout,
  changePassword,
  deleteAccount
} from './cognito'

import {
  loginSchema,
  loginChallengeSchema,
  signupSchema,
  confirmSignupSchema,
  forgotPasswordSchema,
  confirmForgotPasswordSchema,
  resendSignupConfirmationCodeSchema,
  refreshTokenSchema,
  changePasswordSchema
} from './schema'

const app = express()

if (config.trustProxy) {
  // Behind one proxy hop (e.g. an ALB) so req.ip is the client, not the proxy
  app.set('trust proxy', 1)
}

app.use(cors({ origin: config.corsOrigins.length > 0 ? config.corsOrigins : false }))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

// Throttles the unauthenticated endpoints that are targets for brute force, credential stuffing
// and email/SMS spam. Counts are per client IP across all of these routes.
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { type: 'Too Many Requests', message: 'Too many requests, please try again later' },
  skip: () => process.env.NODE_ENV === 'test'
})

app.get('/', (_req: Request, res: Response) => {
  res.json({ message: 'ok' })
})

app.post('/signup', authRateLimit, isValidRequest(signupSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await signup({ email: req.body.email, password: req.body.password, firstname: req.body.firstname, lastname: req.body.lastname })
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/signup/verify', authRateLimit, isValidRequest(confirmSignupSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await confirmSignup(req.body.email, req.body.code)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/signup/resend-code', authRateLimit, isValidRequest(resendSignupConfirmationCodeSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await resendSignupConfirmationCode(req.body.email)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

/**
 * Returns either tokens (AuthenticationResult) or a challenge (ChallengeName, Session and
 * ChallengeParameters). Answer a challenge with POST /login/challenge.
 */
app.post('/login', authRateLimit, isValidRequest(loginSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await login(req.body.email, req.body.password)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/login/challenge', authRateLimit, isValidRequest(loginChallengeSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { challengeName, username, session, answer } = req.body
    const result = await respondToChallenge(challengeName, username, session, answer)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/logout', isAuthed, async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await logout(res.locals.accessToken)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/change-password', isAuthed, isValidRequest(changePasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await changePassword(res.locals.accessToken, req.body.previousPassword, req.body.newPassword)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/forgot-password', authRateLimit, isValidRequest(forgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await forgotPassword(req.body.email)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/forgot-password/confirm', authRateLimit, isValidRequest(confirmForgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await confirmForgotPassword(req.body.email, req.body.password, req.body.code)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/refresh-token', authRateLimit, isValidRequest(refreshTokenSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { accessToken, refreshToken: refresh_token } = req.body

    const result = await refreshToken(accessToken, refresh_token)

    return res.json(result)
  } catch (error) {
    next(error)
  }
})

app.get('/dashboard', isAuthed, async (_req: Request, res: Response) => {
  return res.json({ message: 'ok', user: { sub: res.locals.user.sub, username: res.locals.user.username } })
})

app.delete('/delete-account', isAuthed, async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await deleteAccount(res.locals.accessToken)
    return res.json(result)
  } catch (error) {
    next(error)
  }
})

const unauthorized = (res: Response, message: string) => res.status(401).json({ type: 'Unauthorized', message })
const badRequest = (res: Response, message: string) => res.status(400).json({ type: 'Bad Request', message })

// eslint-disable-next-line @typescript-eslint/no-explicit-any
app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof ZodError) {
    return res.status(400).json({ type: 'Validation', validationErrors: error.issues })
  }

  // Malformed JSON body from express.json()
  if (error?.type === 'entity.parse.failed') {
    return badRequest(res, 'Invalid JSON')
  }

  if (error instanceof MissingTokenError) {
    return unauthorized(res, 'Missing bearer token')
  }

  if (error instanceof JwtExpiredError) {
    return unauthorized(res, 'Token expired')
  }

  // Bad signature, wrong issuer/client/token_use, unparseable token, unknown key id, etc.
  // JWKS fetch failures are our problem, not the caller's, so they fall through to a 500.
  const isJwksError = error instanceof FetchError || error instanceof JwksNotAvailableInCacheError

  if (error instanceof InvalidTokenError || (error instanceof JwtBaseError && !isJwksError)) {
    return unauthorized(res, 'Invalid token')
  }

  // Same response for "no such user" and "wrong password" so the API can't be used to discover
  // which emails are registered. (Set preventUserExistenceErrors on the app client as well.)
  if (error instanceof UserNotFoundException || error instanceof NotAuthorizedException) {
    return unauthorized(res, 'Invalid credentials')
  }

  if (error instanceof UserNotConfirmedException) {
    return res.status(403).json({ type: 'Forbidden', message: 'Account not confirmed' })
  }

  if (error instanceof PasswordResetRequiredException) {
    return res.status(403).json({ type: 'Forbidden', message: 'Password reset required' })
  }

  // Signup can't fully hide whether an email is registered, but don't spell it out
  if (error instanceof UsernameExistsException) {
    return badRequest(res, 'Unable to complete signup')
  }

  if (error instanceof InvalidPasswordException) {
    return badRequest(res, 'Password does not meet requirements')
  }

  if (error instanceof CodeMismatchException) {
    return badRequest(res, 'Invalid confirmation code')
  }

  if (error instanceof ExpiredCodeException) {
    return badRequest(res, 'Confirmation code expired')
  }

  if (error instanceof InvalidParameterException) {
    return badRequest(res, 'Invalid data')
  }

  if (error instanceof LimitExceededException || error instanceof TooManyRequestsException || error instanceof TooManyFailedAttemptsException) {
    return res.status(429).json({ type: 'Too Many Requests', message: 'Too many requests, please try again later' })
  }

  // Anything else (including ResourceNotFoundException, which means the pool or client is
  // misconfigured) is a server error. Log it, but never send internals to the client.
  console.error(error)

  return res.status(500).json({ type: 'Internal Server Error', message: 'Something went wrong' })
})

export default app
