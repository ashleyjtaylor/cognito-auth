import request from 'supertest'

import app from '../src/server'
import { NotAuthorizedException, UserNotFoundException, UsernameExistsException } from '@aws-sdk/client-cognito-identity-provider'
import { JwtExpiredError, JwtInvalidSignatureError } from 'aws-jwt-verify/error'

import { signup, login, respondToChallenge, verifyAccessToken, refreshToken, deleteAccount, changePassword } from '../src/cognito'
import { InvalidTokenError } from '../src/errors'

jest.mock('../src/cognito')

const mocks = {
  signup: jest.mocked(signup),
  login: jest.mocked(login),
  respondToChallenge: jest.mocked(respondToChallenge),
  verifyAccessToken: jest.mocked(verifyAccessToken),
  refreshToken: jest.mocked(refreshToken),
  deleteAccount: jest.mocked(deleteAccount),
  changePassword: jest.mocked(changePassword)
}

const cognitoError = <T>(ErrorClass: new (opts: { message: string, $metadata: object }) => T) => new ErrorClass({ message: 'error', $metadata: {} })

const claims = { sub: 'sub-123', username: 'sub-123', token_use: 'access', client_id: 'client' } as unknown as Awaited<ReturnType<typeof verifyAccessToken>>

describe('server', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('/', () => {
    it('should return ok', async () => {
      await request(app)
        .get('/')
        .expect('Content-Type', /json/)
        .expect(200)
        .then(response => {
          expect(response.body.message).toEqual('ok')
        })
    })
  })

  describe('/signup', () => {
    it('should fail validation from no values', async () => {
      const validationErrors = [
        {
          code: 'invalid_type',
          expected: 'string',
          received: 'undefined',
          path: [
            'body',
            'firstname'
          ],
          message: 'Required'
        },
        {
          code: 'invalid_type',
          expected: 'string',
          received: 'undefined',
          path: [
            'body',
            'lastname'
          ],
          message: 'Required'
        },
        {
          code: 'invalid_type',
          expected: 'string',
          received: 'undefined',
          path: [
            'body',
            'email'
          ],
          message: 'Required'
        },
        {
          code: 'invalid_type',
          expected: 'string',
          received: 'undefined',
          path: [
            'body',
            'password'
          ],
          message: 'Required'
        }
      ]

      await request(app)
        .post('/signup')
        .send({})
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(400)
        .then(response => {
          expect(response.error).toBeTruthy()
          expect(response.body.validationErrors).toHaveLength(4)
          expect(response.body.validationErrors).toEqual(validationErrors)
        })
    })

    it('should fail validation from empty values', async () => {
      const validationErrors = [
        {
          code: 'too_small',
          minimum: 1,
          type: 'string',
          inclusive: true,
          exact: false,
          message: 'Must contain at least one character',
          path: ['body', 'firstname']
        },
        {
          code: 'too_small',
          minimum: 1,
          type: 'string',
          inclusive: true,
          exact: false,
          message: 'Must contain at least one character',
          path: ['body', 'lastname']
        },
        {
          validation: 'email',
          code: 'invalid_string',
          message: 'Invalid email',
          path: ['body', 'email']
        },
        {
          validation: 'regex',
          code: 'invalid_string',
          message: 'Password must contain at least one uppercase character',
          path: ['body', 'password']
        },
        {
          validation: 'regex',
          code: 'invalid_string',
          message: 'Password must contain at least one lowercase character',
          path: ['body', 'password']
        },
        {
          validation: 'regex',
          code: 'invalid_string',
          message: 'Password must contain at least one number',
          path: ['body', 'password']
        },
        {
          validation: 'regex',
          code: 'invalid_string',
          message: 'Password must contain at least one special character',
          path: ['body', 'password']
        },
        {
          type: 'string',
          code: 'too_small',
          exact: false,
          inclusive: true,
          minimum: 8,
          message: 'Password must be at least 8 characters in length',
          path: ['body', 'password']
        }
      ]

      await request(app)
        .post('/signup')
        .send({ firstname: '', lastname: '', email: 'jest', password: '' })
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(400)
        .then(response => {
          expect(response.error).toBeTruthy()
          expect(response.body.validationErrors).toHaveLength(8)
          expect(response.body.validationErrors).toEqual(validationErrors)
        })
    })

    it('should succeed', async () => {
      mocks.signup.mockResolvedValue({
        $metadata: {},
        UserSub: 'user_123',
        UserConfirmed: false,
        CodeDeliveryDetails: {
          Destination: '',
          DeliveryMedium: 'EMAIL',
          AttributeName: ''
        }
      })

      await request(app)
        .post('/signup')
        .send({ firstname: 'jest', lastname: 'test', email: 'jest@exmaple.com', password: 'Password123!' })
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200)
        .then(response => {
          expect(response.body.UserConfirmed).toEqual(false)
        })
    })
  })

  describe('/signup/verify', () => {
    it('should fail validation', async () => {
      await request(app)
        .post('/signup/verify')
        .send({ email: 'jest', code: '' })
        .expect(400)
        .then(response => {
          expect(response.body.validationErrors.map((e: { path: string[] }) => e.path)).toEqual([['body', 'email'], ['body', 'code']])
        })
    })
  })

  describe('/login', () => {
    it('should fail validation', async () => {
      await request(app)
        .post('/login')
        .send({ email: '', password: '' })
        .expect(400)
        .then(response => {
          expect(response.body.validationErrors).toEqual([
            { validation: 'email', code: 'invalid_string', message: 'Invalid email', path: ['body', 'email'] },
            { code: 'too_small', minimum: 1, type: 'string', inclusive: true, exact: false, message: 'Password is required', path: ['body', 'password'] }
          ])
        })
    })

    it('should not apply the new-password policy to existing passwords', async () => {
      mocks.login.mockResolvedValue({ $metadata: {}, AuthenticationResult: { AccessToken: 'token' } })

      await request(app)
        .post('/login')
        .send({ email: 'jest@example.com', password: 'old-weak-password' })
        .expect(200)

      expect(mocks.login).toHaveBeenCalledWith('jest@example.com', 'old-weak-password')
    })

    it('should return the same error for unknown users and wrong passwords', async () => {
      mocks.login.mockRejectedValueOnce(cognitoError(UserNotFoundException))
      const unknownUser = await request(app).post('/login').send({ email: 'jest@example.com', password: 'x' })

      mocks.login.mockRejectedValueOnce(cognitoError(NotAuthorizedException))
      const wrongPassword = await request(app).post('/login').send({ email: 'jest@example.com', password: 'x' })

      expect(unknownUser.status).toEqual(401)
      expect(unknownUser.body).toEqual(wrongPassword.body)
      expect(unknownUser.body).toEqual({ type: 'Unauthorized', message: 'Invalid credentials' })
    })

    it('should pass challenges through to the client', async () => {
      mocks.login.mockResolvedValue({
        $metadata: {},
        ChallengeName: 'NEW_PASSWORD_REQUIRED',
        Session: 'session',
        ChallengeParameters: { USER_ID_FOR_SRP: 'sub-123' }
      })

      await request(app)
        .post('/login')
        .send({ email: 'jest@example.com', password: 'Password123!' })
        .expect(200)
        .then(response => {
          expect(response.body.ChallengeName).toEqual('NEW_PASSWORD_REQUIRED')
          expect(response.body.Session).toEqual('session')
        })
    })
  })

  describe('/login/challenge', () => {
    it('should answer an MFA challenge', async () => {
      mocks.respondToChallenge.mockResolvedValue({ $metadata: {}, AuthenticationResult: { AccessToken: 'token' } })

      await request(app)
        .post('/login/challenge')
        .send({ challengeName: 'SOFTWARE_TOKEN_MFA', username: 'sub-123', session: 'session', answer: '123456' })
        .expect(200)

      expect(mocks.respondToChallenge).toHaveBeenCalledWith('SOFTWARE_TOKEN_MFA', 'sub-123', 'session', '123456')
    })

    it('should apply the password policy to NEW_PASSWORD_REQUIRED answers', async () => {
      await request(app)
        .post('/login/challenge')
        .send({ challengeName: 'NEW_PASSWORD_REQUIRED', username: 'sub-123', session: 'session', answer: 'weak' })
        .expect(400)
        .then(response => {
          expect(response.body.validationErrors.length).toBeGreaterThan(0)
          expect(response.body.validationErrors.every((e: { path: string[] }) => e.path.join('.') === 'body.answer')).toBe(true)
        })

      expect(mocks.respondToChallenge).not.toHaveBeenCalled()
    })

    it('should reject unsupported challenges', async () => {
      await request(app)
        .post('/login/challenge')
        .send({ challengeName: 'CUSTOM_CHALLENGE', username: 'sub-123', session: 'session', answer: 'x' })
        .expect(400)
    })
  })

  describe('authenticated routes', () => {
    it('should require a bearer token', async () => {
      await request(app)
        .get('/dashboard')
        .expect(401)
        .then(response => {
          expect(response.body.message).toEqual('Missing bearer token')
        })

      expect(mocks.verifyAccessToken).not.toHaveBeenCalled()
    })

    it('should ignore tokens sent in the body', async () => {
      await request(app)
        .delete('/delete-account')
        .send({ accessToken: 'token' })
        .expect(401)

      expect(mocks.deleteAccount).not.toHaveBeenCalled()
    })

    it('should accept a valid bearer token and expose the claims', async () => {
      mocks.verifyAccessToken.mockResolvedValue(claims)

      await request(app)
        .get('/dashboard')
        .set('Authorization', 'Bearer token')
        .expect(200)
        .then(response => {
          expect(response.body.user).toEqual({ sub: 'sub-123', username: 'sub-123' })
        })

      expect(mocks.verifyAccessToken).toHaveBeenCalledWith('token')
    })

    it('should return 401 for an expired token', async () => {
      mocks.verifyAccessToken.mockRejectedValue(new JwtExpiredError('expired', 0))

      await request(app)
        .get('/dashboard')
        .set('Authorization', 'Bearer token')
        .expect(401)
        .then(response => {
          expect(response.body.message).toEqual('Token expired')
        })
    })

    it('should return 401, not 500, for a tampered token', async () => {
      mocks.verifyAccessToken.mockRejectedValue(new JwtInvalidSignatureError('bad signature'))

      await request(app)
        .get('/dashboard')
        .set('Authorization', 'Bearer token')
        .expect(401)
        .then(response => {
          expect(response.body.message).toEqual('Invalid token')
        })
    })

    it('should use the bearer token for Cognito calls', async () => {
      mocks.verifyAccessToken.mockResolvedValue(claims)
      mocks.changePassword.mockResolvedValue({ $metadata: {} })

      await request(app)
        .post('/change-password')
        .set('Authorization', 'Bearer token')
        .send({ previousPassword: 'old-weak-password', newPassword: 'NewPassword123!' })
        .expect(200)

      expect(mocks.changePassword).toHaveBeenCalledWith('token', 'old-weak-password', 'NewPassword123!')
    })
  })

  describe('/refresh-token', () => {
    it('should refresh with an expired access token', async () => {
      mocks.refreshToken.mockResolvedValue({ $metadata: {}, AuthenticationResult: { AccessToken: 'new-token' } })

      await request(app)
        .post('/refresh-token')
        .send({ accessToken: 'expired-token', refreshToken: 'refresh' })
        .expect(200)

      expect(mocks.refreshToken).toHaveBeenCalledWith('expired-token', 'refresh')
      expect(mocks.verifyAccessToken).not.toHaveBeenCalled()
    })

    it('should return 401 for an unreadable access token', async () => {
      mocks.refreshToken.mockRejectedValue(new InvalidTokenError())

      await request(app)
        .post('/refresh-token')
        .send({ accessToken: 'garbage', refreshToken: 'refresh' })
        .expect(401)
    })
  })

  describe('errors', () => {
    it('should not leak internal errors', async () => {
      const consoleError = jest.spyOn(console, 'error').mockImplementation(() => undefined)
      mocks.signup.mockRejectedValue(Object.assign(new Error('internal detail'), { secret: 'value' }))

      await request(app)
        .post('/signup')
        .send({ firstname: 'jest', lastname: 'test', email: 'jest@example.com', password: 'Password123!' })
        .expect(500)
        .then(response => {
          expect(response.body).toEqual({ type: 'Internal Server Error', message: 'Something went wrong' })
        })

      consoleError.mockRestore()
    })

    it('should not reveal that an email is already registered', async () => {
      mocks.signup.mockRejectedValue(cognitoError(UsernameExistsException))

      await request(app)
        .post('/signup')
        .send({ firstname: 'jest', lastname: 'test', email: 'jest@example.com', password: 'Password123!' })
        .expect(400)
        .then(response => {
          expect(response.body.message).toEqual('Unable to complete signup')
        })
    })

    it('should return 400 for malformed JSON', async () => {
      await request(app)
        .post('/login')
        .set('Content-Type', 'application/json')
        .send('{bad json')
        .expect(400)
    })
  })
})
