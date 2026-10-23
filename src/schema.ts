import { z } from 'zod'

// Mirrors the user pool password policy. Only used where a NEW password is being set:
// existing passwords are checked by Cognito, so login must not reject them against this policy.
const newPasswordSchema = z.string()
  .regex(new RegExp('.*[A-Z].*'), 'Password must contain at least one uppercase character')
  .regex(new RegExp('.*[a-z].*'), 'Password must contain at least one lowercase character')
  .regex(new RegExp('.*\\d.*'), 'Password must contain at least one number')
  .regex(
    new RegExp('.*[`~<>?,./!@#$%^&*()\\-_+="\'|{}\\[\\];:\\\\].*'),
    'Password must contain at least one special character'
  )
  .min(8, 'Password must be at least 8 characters in length')

const existingPasswordSchema = z.string().min(1, 'Password is required')

const nameSchema = z.string().min(1, 'Must contain at least one character')

const emailSchema = z.string().email()

const codeSchema = z.string().min(1, 'Code is required')

export const challengeNames = ['NEW_PASSWORD_REQUIRED', 'SOFTWARE_TOKEN_MFA', 'SMS_MFA'] as const

export type ChallengeName = typeof challengeNames[number]

export const signupSchema = z.object({
  body: z.object({
    firstname: nameSchema,
    lastname: nameSchema,
    email: emailSchema,
    password: newPasswordSchema
  })
})

export const confirmSignupSchema = z.object({
  body: z.object({
    email: emailSchema,
    code: codeSchema
  })
})

export const resendSignupConfirmationCodeSchema = z.object({
  body: z.object({
    email: emailSchema
  })
})

export const loginSchema = z.object({
  body: z.object({
    email: emailSchema,
    password: existingPasswordSchema
  })
})

export const loginChallengeSchema = z.object({
  body: z.object({
    challengeName: z.enum(challengeNames),
    // ChallengeParameters.USER_ID_FOR_SRP from the /login response
    username: z.string().min(1),
    session: z.string().min(1),
    // The new password for NEW_PASSWORD_REQUIRED, or the MFA code
    answer: z.string().min(1)
  }).superRefine((body, ctx) => {
    if (body.challengeName === 'NEW_PASSWORD_REQUIRED') {
      const result = newPasswordSchema.safeParse(body.answer)

      if (!result.success) {
        result.error.issues.forEach(issue => ctx.addIssue({ ...issue, path: ['answer'] }))
      }
    }
  })
})

export const changePasswordSchema = z.object({
  body: z.object({
    previousPassword: existingPasswordSchema,
    newPassword: newPasswordSchema
  })
})

export const forgotPasswordSchema = z.object({
  body: z.object({
    email: emailSchema
  })
})

export const confirmForgotPasswordSchema = z.object({
  body: z.object({
    email: emailSchema,
    password: newPasswordSchema,
    code: codeSchema
  })
})

export const refreshTokenSchema = z.object({
  body: z.object({
    // The current (usually expired) access token, used only to identify the user for SECRET_HASH
    accessToken: z.string().min(1),
    refreshToken: z.string().min(1)
  })
})
