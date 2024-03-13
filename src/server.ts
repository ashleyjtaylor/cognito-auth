import express, { ErrorRequestHandler, NextFunction, Request, Response } from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import { ZodError } from 'zod'
import { JwtExpiredError } from 'aws-jwt-verify/error'
import {
  CodeMismatchException,
  InvalidParameterException,
  NotAuthorizedException,
  ResourceNotFoundException,
  UserNotFoundException
} from '@aws-sdk/client-cognito-identity-provider'

import { isAuthed, isValidRequest } from './middleware'

import {
  login,
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
  logoutSchema,
  signupSchema,
  confirmSignupSchema,
  verifyTokenSchema,
  forgotPasswordSchema,
  confirmForgotPasswordSchema,
  resendSignupConfirmationCodeSchema,
  refreshTokenSchema,
  changePasswordSchema,
  deleteAccountSchema
} from './schema'

const app = express()

app.use(cors())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.get('/', (_req: Request, res: Response) => {
  res.json({ message: 'ok' })
})

app.post('/signup', isValidRequest(signupSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await signup({ email: req.body.email, password: req.body.password, firstname: req.body.firstname, lastname: req.body.lastname })
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/signup/verify', isValidRequest(confirmSignupSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await confirmSignup(req.body.email, req.body.code)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/signup/resend-code', isValidRequest(resendSignupConfirmationCodeSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await resendSignupConfirmationCode(req.body.email)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/login', isValidRequest(loginSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await login(req.body.email, req.body.password)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/logout', isValidRequest(logoutSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await logout(req.body.accessToken)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/change-password', isValidRequest(changePasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await changePassword(req.body.accessToken, req.body.previousPassword, req.body.newPassword)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/forgot-password', isValidRequest(forgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await forgotPassword(req.body.email)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/forgot-password/confirm', isValidRequest(confirmForgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await confirmForgotPassword(req.body.email, req.body.password, req.body.code)
    return res.json(result)
  } catch (err) {
    next(err)
  }
})

app.post('/refresh-token', isValidRequest(refreshTokenSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { accessToken, refreshToken: refresh_token } = req.body

    const result = await refreshToken(accessToken, refresh_token)

    return res.json(result)
  } catch (error) {
    next(error)
  }
})

app.get('/dashboard', isValidRequest(verifyTokenSchema), isAuthed, async (_req: Request, res: Response, _next: NextFunction) => {
  return res.json({ message: 'ok' })
})

app.delete('/delete-account', isValidRequest(deleteAccountSchema), isAuthed, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await deleteAccount(req.body.accessToken)
    return res.json(result)
  } catch (error) {
    next(error)
  }
})

app.use((error: ErrorRequestHandler, _req: Request, res: Response, _next: NextFunction) => {
  console.log(error)

  if (error instanceof ZodError) {
    return res.status(500).json({ type: 'Validation', validationErrors: error.issues })
  }

  if (error instanceof JwtExpiredError) {
    return res.status(401).json({ type: 'Unauthorized', message: 'Token expired' })
  }

  if (error instanceof UserNotFoundException) {
    return res.status(401).json({ type: 'Unauthorized', message: 'Invalid user' })
  }

  if (error instanceof NotAuthorizedException) {
    return res.status(401).json({ type: 'Unauthorized', message: 'Invalid credentials' })
  }

  if (error instanceof InvalidParameterException) {
    return res.status(400).json({ type: 'Bad Request', message: 'Invalid data' })
  }

  if (error instanceof CodeMismatchException) {
    return res.status(400).json({ type: 'Bad Request', message: 'Invalid confirmation code' })
  }

  if (error instanceof ResourceNotFoundException) {
    return res.status(404).json({ type: 'Not Found', message: 'Resource not found' })
  }

  return res.status(500).json(error)
})

export default app
