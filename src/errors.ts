export class InvalidTokenError extends Error {
  constructor(message = 'Invalid token') {
    super(message)
    this.name = 'InvalidTokenError'
  }
}

export class MissingTokenError extends Error {
  constructor(message = 'Missing bearer token') {
    super(message)
    this.name = 'MissingTokenError'
  }
}
