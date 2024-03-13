import { z } from 'zod'

const passwordSchema = z.string()
  .regex(new RegExp('.*[A-Z].*'), 'Password must contain at least one uppercase character')
  .regex(new RegExp('.*[a-z].*'), 'Password must contain at least one lowercase character')
  .regex(new RegExp('.*\\d.*'), 'Password must contain at least one number')
  .regex(
    new RegExp('.*[`~<>?,./!@#$%^&*()\\-_+="\'|{}\\[\\];:\\\\].*'),
    'Password must contain at least one special character'
  )
  .min(8, 'Password must be at least 8 characters in length')

const nameSchema = z.string().min(1, 'Must contain at least one character')

export const signupSchema = z.object({
  body: z.object({
    firstname: nameSchema,
    lastname: nameSchema,
    email: z.string().email(),
    password: passwordSchema
  })
})

export const confirmSignupSchema = z.object({
  body: z.object({
    email: z.string().email(),
    code: z.string()
  })
})

export const resendSignupConfirmationCodeSchema = z.object({
  body: z.object({
    email: z.string()
  })
})

export const loginSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: passwordSchema
  })
})

export const logoutSchema = z.object({
  body: z.object({
    accessToken: z.string()
  })
})

export const verifyTokenSchema = z.object({
  body: z.object({
    accessToken: z.string()
  })
})

export const changePasswordSchema = z.object({
  body: z.object({
    accessToken: z.string(),
    previousPassword: passwordSchema,
    newPassword: passwordSchema
  })
})

export const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.string()
  })
})

export const confirmForgotPasswordSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: passwordSchema,
    code: z.string()
  })
})

export const refreshTokenSchema = z.object({
  body: z.object({
    accessToken: z.string(),
    refreshToken: z.string()
  })
})

export const deleteAccountSchema = z.object({
  body: z.object({
    accessToken: z.string()
  })
})
