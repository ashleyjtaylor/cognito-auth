#!/usr/bin/env node
import 'source-map-support/register'
import * as cdk from 'aws-cdk-lib'
import { AuthStack } from '../lib/auth-stack'

const app = new cdk.App()

new AuthStack(app, 'AuthStack', {
  env: { account: '780544746325', region: 'eu-west-1' }
})
