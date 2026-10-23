import { CognitoIdentityProviderClient, InitiateAuthCommand, RespondToAuthChallengeCommand } from '@aws-sdk/client-cognito-identity-provider'

import { createSecretHash, refreshToken, respondToChallenge } from '../src/cognito'
import { InvalidTokenError } from '../src/errors'

const base64url = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')

// Unsigned token with Cognito-shaped access token claims. refreshToken only reads the username.
const accessToken = (payload: object) => `${base64url({ alg: 'RS256', kid: 'kid' })}.${base64url(payload)}.signature`

const expiredAccessToken = accessToken({
  sub: 'sub-123',
  username: 'sub-123',
  token_use: 'access',
  client_id: process.env.COGNITO_CLIENT_ID,
  exp: Math.floor(Date.now() / 1000) - 3600
})

describe('cognito', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let send: jest.Mock<Promise<object>, [any]>

  beforeEach(() => {
    send = jest.fn().mockResolvedValue({ AuthenticationResult: {} })
    jest.spyOn(CognitoIdentityProviderClient.prototype, 'send').mockImplementation(send as never)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('refreshToken', () => {
    it('should work with an expired access token, without calling GetUser', async () => {
      await refreshToken(expiredAccessToken, 'refresh-token')

      expect(send).toHaveBeenCalledTimes(1)

      const command = send.mock.calls[0][0]
      expect(command).toBeInstanceOf(InitiateAuthCommand)
      expect(command.input).toEqual({
        ClientId: process.env.COGNITO_CLIENT_ID,
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        AuthParameters: {
          REFRESH_TOKEN: 'refresh-token',
          // SECRET_HASH must use the Cognito username (the sub), not the email
          SECRET_HASH: createSecretHash('sub-123')
        }
      })
    })

    it('should reject tokens that are not access tokens for this client', async () => {
      const idToken = accessToken({ username: 'sub-123', token_use: 'id', client_id: process.env.COGNITO_CLIENT_ID })
      const otherClient = accessToken({ username: 'sub-123', token_use: 'access', client_id: 'other-client' })

      await expect(refreshToken(idToken, 'refresh-token')).rejects.toBeInstanceOf(InvalidTokenError)
      await expect(refreshToken(otherClient, 'refresh-token')).rejects.toBeInstanceOf(InvalidTokenError)
      await expect(refreshToken('not-a-jwt', 'refresh-token')).rejects.toBeInstanceOf(InvalidTokenError)

      expect(send).not.toHaveBeenCalled()
    })
  })

  describe('respondToChallenge', () => {
    it('should send the answer under the right key with a secret hash', async () => {
      await respondToChallenge('SOFTWARE_TOKEN_MFA', 'sub-123', 'session', '123456')

      const command = send.mock.calls[0][0]
      expect(command).toBeInstanceOf(RespondToAuthChallengeCommand)
      expect(command.input).toEqual({
        ClientId: process.env.COGNITO_CLIENT_ID,
        ChallengeName: 'SOFTWARE_TOKEN_MFA',
        Session: 'session',
        ChallengeResponses: {
          USERNAME: 'sub-123',
          SECRET_HASH: createSecretHash('sub-123'),
          SOFTWARE_TOKEN_MFA_CODE: '123456'
        }
      })
    })

    it('should send a new password as NEW_PASSWORD', async () => {
      await respondToChallenge('NEW_PASSWORD_REQUIRED', 'sub-123', 'session', 'NewPassword123!')

      expect(send.mock.calls[0][0].input.ChallengeResponses.NEW_PASSWORD).toEqual('NewPassword123!')
    })
  })
})
