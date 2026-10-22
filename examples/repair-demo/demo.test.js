import test from 'node:test';
import assert from 'node:assert/strict';
import { healthStatus } from './health.js';
test('synthetic service reports healthy',()=>assert.equal(healthStatus(),'healthy'));
