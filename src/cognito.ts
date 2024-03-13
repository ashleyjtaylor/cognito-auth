import { createHmac } from 'crypto'
import { CognitoJwtVerifier } from 'aws-jwt-verify'

import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  SignUpCommandInput,
  InitiateAuthCommand,
  InitiateAuthCommandInput,
  ConfirmSignUpCommand,
  ConfirmSignUpCommandInput,
  ForgotPasswordCommand,
  ForgotPasswordCommandInput,
  ConfirmForgotPasswordCommand,
  ConfirmForgotPasswordCommandInput,
  ResendConfirmationCodeCommand,
  ResendConfirmationCodeCommandInput,
  GetUserCommand,
  GetUserCommandInput,
  GlobalSignOutCommand,
  GlobalSignOutCommandInput,
  ChangePasswordCommand,
  ChangePasswordCommandInput,
  DeleteUserCommand,
  DeleteUserCommandInput
} from '@aws-sdk/client-cognito-identity-provider'

const verifier = CognitoJwtVerifier.create({
  tokenUse: 'access',
  userPoolId: process.env.COGNITO_USER_POOL_ID as string,
  clientId: process.env.COGNITO_CLIENT_ID as string
})

const createSecretHash = (value?: string) => {
  if (!value) throw new Error('Invalid value for hashing')

  const hasher = createHmac('sha256', process.env.COGNITO_CLIENT_SECRET as string)
  hasher.update(`${value}${process.env.COGNITO_CLIENT_ID}`)

  return hasher.digest('base64')
}

const fetchUser = async (accessToken: string) => {
  const input: GetUserCommandInput = {
    AccessToken: accessToken
  }

  const command = new GetUserCommand(input)
  const response = await client.send(command)

  return response
}

const client = new CognitoIdentityProviderClient({
  region: 'eu-west-1'
})

type SignUp = {
  email: string;
  password: string;
  firstname: string;
  lastname: string;
}

export const signup = async (user: SignUp) => {
  const { email, password, firstname, lastname } = user

  const input: SignUpCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
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

  const command = new SignUpCommand(input)
  const response = await client.send(command)

  return response
}

export const confirmSignup = async (email: string, code: string) => {
  const input: ConfirmSignUpCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    SecretHash: createSecretHash(email),
    Username: email,
    ConfirmationCode: code
  }

  const command = new ConfirmSignUpCommand(input)
  const response = await client.send(command)

  return response
}

export const resendSignupConfirmationCode = async (email: string) => {
  const input: ResendConfirmationCodeCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    Username: email,
    SecretHash: createSecretHash(email)
  }

  const command = new ResendConfirmationCodeCommand(input)
  const response = await client.send(command)

  return response
}

export const login = async (email: string, password: string) => {
  const input: InitiateAuthCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    AuthFlow: 'USER_PASSWORD_AUTH',
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: createSecretHash(email)
    }
  }

  const command = new InitiateAuthCommand(input)
  const response = await client.send(command)

  return response
}

export const logout = async (accessToken: string) => {
  const input: GlobalSignOutCommandInput = {
    AccessToken: accessToken
  }

  const command = new GlobalSignOutCommand(input)

  const response = await client.send(command)

  return response
}

export const forgotPassword = async (email: string) => {
  const input: ForgotPasswordCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    SecretHash: createSecretHash(email),
    Username: email
  }

  const command = new ForgotPasswordCommand(input)
  const response = await client.send(command)

  return response
}

export const confirmForgotPassword = async (email: string, password: string, code: string) => {
  const input: ConfirmForgotPasswordCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    SecretHash: createSecretHash(email),
    Username: email,
    Password: password,
    ConfirmationCode: code
  }

  const command = new ConfirmForgotPasswordCommand(input)
  const response = await client.send(command)

  return response
}

export const changePassword = async (accessToken: string, previousPassword: string, newPassword: string) => {
  const input: ChangePasswordCommandInput = {
    AccessToken: accessToken,
    PreviousPassword: previousPassword,
    ProposedPassword: newPassword
  }

  const command = new ChangePasswordCommand(input)
  const response = await client.send(command)

  return response
}

export const verifyToken = async (accessToken: string) => {
  await verifier.verify(accessToken)
  await fetchUser(accessToken)
}

export const refreshToken = async (accessToken: string, refreshToken: string) => {
  const user = await fetchUser(accessToken)

  if (!user) {
    throw new Error('Invalid user')
  }

  const input: InitiateAuthCommandInput = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    AuthFlow: 'REFRESH_TOKEN_AUTH',
    AuthParameters: {
      REFRESH_TOKEN: refreshToken,
      SECRET_HASH: createSecretHash(user.Username)
    }
  }

  const command = new InitiateAuthCommand(input)
  const response = await client.send(command)

  return response
}

export const deleteAccount = async (accessToken: string) => {
  const input: DeleteUserCommandInput = {
    AccessToken: accessToken
  }

  const command = new DeleteUserCommand(input)
  const response = await client.send(command)

  return response
}
