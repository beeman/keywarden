#!/usr/bin/env node

import { greet } from './index'

function main() {
  const name = process.argv[2] || 'World'
  console.log(greet(name))
}

main()
