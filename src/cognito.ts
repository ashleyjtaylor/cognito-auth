import { createHmac } from 'crypto'
import { CognitoJwtVerifier } from 'aws-jwt-verify'
import { decomposeUnverifiedJwt } from 'aws-jwt-verify/jwt'

import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  SignUpCommandInput,
  InitiateAuthCommand,
  InitiateAuthCommandInput,
  RespondToAuthChallengeCommand,
  RespondToAuthChallengeCommandInput,
  ChallengeNameType,
  ConfirmSignUpCommand,
  ConfirmSignUpCommandInput,
  ForgotPasswordCommand,
  ForgotPasswordCommandInput,
  ConfirmForgotPasswordCommand,
  ConfirmForgotPasswordCommandInput,
  ResendConfirmationCodeCommand,
  ResendConfirmationCodeCommandInput,
  GlobalSignOutCommand,
  GlobalSignOutCommandInput,
  ChangePasswordCommand,
  ChangePasswordCommandInput,
  DeleteUserCommand,
  DeleteUserCommandInput
} from '@aws-sdk/client-cognito-identity-provider'

import { config } from './config'
import { InvalidTokenError } from './errors'
import { ChallengeName } from './schema'

const verifier = CognitoJwtVerifier.create({
  tokenUse: 'access',
  userPoolId: config.userPoolId,
  clientId: config.clientId
})

const client = new CognitoIdentityProviderClient({
  region: config.region
})

export const createSecretHash = (username?: string) => {
  if (!username) throw new Error('Invalid value for hashing')

  const hasher = createHmac('sha256', config.clientSecret)
  hasher.update(`${username}${config.clientId}`)

  return hasher.digest('base64')
}

type SignUp = {
  email: string;
  password: string;
  firstname: string;
  lastname: string;
}

export const signup = async (user: SignUp) => {
  const { email, password, firstname, lastname } = user

  const input: SignUpCommandInput = {
    ClientId: config.clientId,
    Username: email,
    Password: password,
    UserAttributes: [
      {
        Name: 'given_name',
        Value: firstname
      },
      {
        Name: 'family_name',
        Value: lastname
      },
      {
        Name: 'name',
        Value: `${firstname} ${lastname}`
      }
    ],
    SecretHash: createSecretHash(email)
  }

  return client.send(new SignUpCommand(input))
}

export const confirmSignup = async (email: string, code: string) => {
  const input: ConfirmSignUpCommandInput = {
    ClientId: config.clientId,
    SecretHash: createSecretHash(email),
    Username: email,
    ConfirmationCode: code
  }

  return client.send(new ConfirmSignUpCommand(input))
}

export const resendSignupConfirmationCode = async (email: string) => {
  const input: ResendConfirmationCodeCommandInput = {
    ClientId: config.clientId,
    Username: email,
    SecretHash: createSecretHash(email)
  }

  return client.send(new ResendConfirmationCodeCommand(input))
}

/**
 * May return tokens (AuthenticationResult) or a challenge (ChallengeName + Session + ChallengeParameters),
 * e.g. NEW_PASSWORD_REQUIRED or an MFA code. Challenges are answered via respondToChallenge.
 */
export const login = async (email: string, password: string) => {
  const input: InitiateAuthCommandInput = {
    ClientId: config.clientId,
    AuthFlow: 'USER_PASSWORD_AUTH',
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: createSecretHash(email)
    }
  }

  return client.send(new InitiateAuthCommand(input))
}

// Which ChallengeResponses key carries the user's answer for each supported challenge
const challengeAnswerKeys: Record<ChallengeName, string> = {
  [ChallengeNameType.NEW_PASSWORD_REQUIRED]: 'NEW_PASSWORD',
  [ChallengeNameType.SOFTWARE_TOKEN_MFA]: 'SOFTWARE_TOKEN_MFA_CODE',
  [ChallengeNameType.SMS_MFA]: 'SMS_MFA_CODE'
}

/**
 * @param username the ChallengeParameters.USER_ID_FOR_SRP value returned with the challenge
 */
export const respondToChallenge = async (challengeName: ChallengeName, username: string, session: string, answer: string) => {
  const input: RespondToAuthChallengeCommandInput = {
    ClientId: config.clientId,
    ChallengeName: challengeName,
    Session: session,
    ChallengeResponses: {
      USERNAME: username,
      SECRET_HASH: createSecretHash(username),
      [challengeAnswerKeys[challengeName]]: answer
    }
  }

  return client.send(new RespondToAuthChallengeCommand(input))
}

export const logout = async (accessToken: string) => {
  const input: GlobalSignOutCommandInput = {
    AccessToken: accessToken
  }

  return client.send(new GlobalSignOutCommand(input))
}

export const forgotPassword = async (email: string) => {
  const input: ForgotPasswordCommandInput = {
    ClientId: config.clientId,
    SecretHash: createSecretHash(email),
    Username: email
  }

  return client.send(new ForgotPasswordCommand(input))
}

export const confirmForgotPassword = async (email: string, password: string, code: string) => {
  const input: ConfirmForgotPasswordCommandInput = {
    ClientId: config.clientId,
    SecretHash: createSecretHash(email),
    Username: email,
    Password: password,
    ConfirmationCode: code
  }

  return client.send(new ConfirmForgotPasswordCommand(input))
}

export const changePassword = async (accessToken: string, previousPassword: string, newPassword: string) => {
  const input: ChangePasswordCommandInput = {
    AccessToken: accessToken,
    PreviousPassword: previousPassword,
    ProposedPassword: newPassword
  }

  return client.send(new ChangePasswordCommand(input))
}

/**
 * Verifies the access token locally (signature, expiry, issuer, client id, token_use) against the
 * user pool's cached JWKS. No call to Cognito per request.
 *
 * Note: this does not detect tokens revoked by GlobalSignOut before they expire, so keep the
 * access token lifetime short. Cognito APIs that take an access token (ChangePassword,
 * DeleteUser, GlobalSignOut) still check revocation themselves.
 */
export const verifyAccessToken = async (accessToken: string) => {
  return verifier.verify(accessToken)
}

/**
 * Reads the Cognito username from an access token that is allowed to be expired.
 *
 * The token is not trusted for authentication here: Cognito validates the refresh token and
 * the SECRET_HASH, and the refresh token is bound to the user, so a wrong username just fails.
 */
const usernameFromAccessToken = (accessToken: string) => {
  let payload

  try {
    payload = decomposeUnverifiedJwt(accessToken).payload
  } catch (_error) {
    throw new InvalidTokenError()
  }

  if (payload.token_use !== 'access' || payload.client_id !== config.clientId || typeof payload.username !== 'string') {
    throw new InvalidTokenError()
  }

  return payload.username
}

/**
 * @param accessToken the (possibly expired) access token, needed only to read the username for SECRET_HASH
 */
export const refreshToken = async (accessToken: string, refreshToken: string) => {
  const username = usernameFromAccessToken(accessToken)

  const input: InitiateAuthCommandInput = {
    ClientId: config.clientId,
    AuthFlow: 'REFRESH_TOKEN_AUTH',
    AuthParameters: {
      REFRESH_TOKEN: refreshToken,
      SECRET_HASH: createSecretHash(username)
    }
  }

  return client.send(new InitiateAuthCommand(input))
}

export const deleteAccount = async (accessToken: string) => {
  const input: DeleteUserCommandInput = {
    AccessToken: accessToken
  }

  return client.send(new DeleteUserCommand(input))
}
