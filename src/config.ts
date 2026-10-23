const required = (name: string): string => {
  const value = process.env[name]

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`)
  }

  return value
}

const userPoolId = required('COGNITO_USER_POOL_ID')

export const config = {
  userPoolId,
  clientId: required('COGNITO_CLIENT_ID'),
  clientSecret: required('COGNITO_CLIENT_SECRET'),
  // User pool IDs are prefixed with their region, e.g. eu-west-1_AbCdEf123
  region: process.env.AWS_REGION || userPoolId.split('_')[0],
  // Comma-separated list of origins allowed to call the API from a browser. Empty = no cross-origin access.
  corsOrigins: (process.env.CORS_ORIGINS || '').split(',').map(origin => origin.trim()).filter(Boolean),
  // Set when running behind a load balancer / reverse proxy so rate limiting sees the real client IP.
  trustProxy: process.env.TRUST_PROXY === 'true'
}
