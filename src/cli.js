#!/usr/bin/env node
import fs from 'node:fs/promises';
import { scan } from './index.js';

const file = process.argv[2];
if (!file) {
  console.error('Usage: jevshield <input.json>');
  process.exit(2);
}
try {
  const result = scan(JSON.parse(await fs.readFile(file, 'utf8')));
  console.log(JSON.stringify(result, null, 2));
  if (result.decision === 'BLOCK') process.exitCode = 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
}
