import { Stack, StackProps, Duration, RemovalPolicy } from 'aws-cdk-lib'
import { Construct } from 'constructs'
import { UserPool, VerificationEmailStyle, AccountRecovery, UserPoolClient, OAuthScope } from 'aws-cdk-lib/aws-cognito'

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
      removalPolicy: RemovalPolicy.DESTROY
    })

    new UserPoolClient(this, 'UserPoolClient', {
      userPool,
      userPoolClientName: 'cognito-auth-user-pool-client',
      generateSecret: true,
      authFlows: {
        adminUserPassword: true,
        userPassword: true,
        custom: true
      },
      oAuth: {
        flows: {
          implicitCodeGrant: true
        },
        scopes: [OAuthScope.EMAIL, OAuthScope.OPENID, OAuthScope.PROFILE],
        callbackUrls: ['http://localhost:3000/api/auth/callback']
      }
    })
  }
}
