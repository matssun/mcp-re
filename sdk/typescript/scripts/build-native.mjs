// SPDX-License-Identifier: Apache-2.0
//
// Build the native addon with Bazel and stage the package's native/ directory:
//
//   node scripts/build-native.mjs            # -c opt, the published artifact
//   node scripts/build-native.mjs --debug    # fastbuild
//
// Bazel compiles //sdk/typescript:native (the `.node`) and :native_type_defs (what
// napi-derive states about the exports); write-binding.mjs renders native/binding.js and
// native/binding.d.ts from the latter with the pinned @napi-rs/cli.
import { execFileSync } from 'node:child_process'
import { copyFileSync, chmodSync, mkdirSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ADDON = '//sdk/typescript:native'
const TYPE_DEFS = '//sdk/typescript:native_type_defs'

const pkg = resolve(fileURLToPath(new URL('..', import.meta.url)))
const workspace = resolve(pkg, '..', '..')
const flags = process.argv.includes('--debug') ? [] : ['-c', 'opt']

const bazel = (...args) =>
  execFileSync('bazel', args, { cwd: workspace, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'inherit'] })

bazel('build', ...flags, ADDON, TYPE_DEFS)
const execRoot = bazel('info', ...flags, 'execution_root').trim()
// The configured output path, not bazel-bin: bazel-bin names whichever configuration
// built last.
const output = (label) => {
  const files = bazel('cquery', ...flags, '--output=files', label).trim().split('\n').filter(Boolean)
  if (files.length !== 1) throw new Error(`${label}: expected one output, got ${files.length}`)
  return join(execRoot, files[0])
}

const nativeDir = join(pkg, 'native')
mkdirSync(nativeDir, { recursive: true })
const addon = output(ADDON)
const staged = join(nativeDir, basename(addon))
copyFileSync(addon, staged)
chmodSync(staged, 0o755)
console.log(`build-native: ${ADDON} -> native/${basename(addon)}`)

execFileSync(process.execPath, [join(pkg, 'scripts', 'write-binding.mjs'), output(TYPE_DEFS), nativeDir], {
  cwd: pkg,
  stdio: 'inherit',
})
