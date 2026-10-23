import { Stack, StackProps, Duration, RemovalPolicy } from 'aws-cdk-lib'
import { Construct } from 'constructs'
import { UserPool, VerificationEmailStyle, AccountRecovery, UserPoolClient, Mfa } from 'aws-cdk-lib/aws-cognito'

export class AuthStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props)

    const userPool = new UserPool(this, 'UserPool', {
      userPoolName: 'cognito-auth-user-pool',
      signInCaseSensitive: false,
      selfSignUpEnabled: true,
      accountRecovery: AccountRecovery.EMAIL_ONLY,
      signInAliases: {
        email: true
      },
      userVerification: {
        emailSubject: 'Verify your email for cognito-auth!',
        emailBody: 'Thanks for signing up to cognito-auth! Your verification code is {####}',
        emailStyle: VerificationEmailStyle.CODE,
        smsMessage: 'Thanks for signing up to cognito-auth! Your verification code is {####}'
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(3)
      },
      standardAttributes: {
        givenName: {
          required: true
        },
        familyName: {
          required: true
        },
        fullname: {
          required: true
        }
      },
      // Optional TOTP (authenticator app) MFA. Users who enable it get a SOFTWARE_TOKEN_MFA
      // challenge from /login, answered via /login/challenge.
      mfa: Mfa.OPTIONAL,
      mfaSecondFactor: {
        otp: true,
        sms: false
      },
      // Never delete user accounts along with the stack
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN
    })

    new UserPoolClient(this, 'UserPoolClient', {
      userPool,
      userPoolClientName: 'cognito-auth-user-pool-client',
      generateSecret: true,
      // Only the flow the API uses. REFRESH_TOKEN_AUTH is always enabled.
      authFlows: {
        userPassword: true
      },
      // The API talks to the Cognito API directly; no Hosted UI / OAuth flows. This has to be explicit,
      // because CDK enables the authorization code and implicit grants by default.
      disableOAuth: true,
      // "User does not exist" errors become generic "incorrect username or password" errors
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      // Short-lived access/ID tokens, since the API verifies them locally and can't see revocations
      accessTokenValidity: Duration.minutes(15),
      idTokenValidity: Duration.minutes(15),
      refreshTokenValidity: Duration.days(30)
    })
  }
}
