import request from 'supertest'

import app from '../src/server'
import { signup, login } from '../src/cognito'

jest.mock('../src/cognito')

const mocks = {
  signup: jest.mocked(signup),
  login: jest.mocked(login)
}

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
        .expect(500)
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
        .expect(500)
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

  xdescribe('/signup/verify', () => {
    it('should fail validation', async () => {
      const validationErrors = [
        {
          validation: 'email',
          code: 'invalid_string',
          message: 'Invalid email',
          path: ['body', 'email']
        },
        {
          validation: 'string',
          code: 'too_small',
          exact: false,
          inclusive: true,
          message: 'Password must contain at least one uppercase character',
          path: ['body', 'code']
        }
      ]

      await request(app)
        .post('/signup/verify')
        .send({ email: 'jest', code: '' })
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(500)
        .then(response => {
          expect(response.error).toBeTruthy()
          expect(response.body.validationErrors).toHaveLength(2)
          expect(response.body.validationErrors).toEqual(validationErrors)
        })
    })

    xit('should succeed', async () => {
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
        .send({ email: 'jest@exmaple.com', password: 'Password123!' })
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200)
        .then(response => {
          expect(response.body.UserConfirmed).toEqual(false)
        })
    })
  })

  xdescribe('/login', () => {
    it('should fail validation', async () => {
      const validationErrors = [
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
          message: 'Must contain at least one special character',
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
        .post('/login')
        .send({ email: '', password: '' })
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(500)
        .then(response => {
          expect(response.error).toBeTruthy()
          expect(response.body.validationErrors).toHaveLength(6)
          expect(response.body.validationErrors).toEqual(validationErrors)
        })
    })

    it('should succeed', async () => {
      await request(app)
        .post('/login')
        .send({ email: 'jest@exmaple.com', password: 'Password123!' })
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200)
    })
  })
})
