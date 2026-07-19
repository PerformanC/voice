import fs from 'node:fs'
import path from 'node:path'

const [kind, targetArch] = process.argv.slice(2)
const archNames = {
  arm64: 'ARM64',
  ia32: 'Win32',
  x64: 'x64'
}
const vcpkgArchNames = {
  arm64: 'arm64',
  ia32: 'x86',
  x64: 'x64'
}

if (!['include', 'library'].includes(kind) || !archNames[targetArch]) {
  fail(`Unsupported libsodium lookup: ${kind ?? ''} ${targetArch ?? ''}`)
}

const roots = []
const sodiumRoot = process.env.SODIUM_ROOT ?? process.env.npm_config_sodium_root

if (sodiumRoot) {
  roots.push(sodiumRoot)
  roots.push(vcpkgInstalledRoot(sodiumRoot))
}

if (process.env.VCPKG_ROOT) {
  roots.push(vcpkgInstalledRoot(process.env.VCPKG_ROOT))
}

const candidates =
  kind === 'include'
    ? includeCandidates(roots)
    : libraryCandidates(roots, targetArch)
const result = candidates.find(
  (candidate) => candidate && fs.existsSync(candidate)
)

if (!result) {
  fail(
    `Could not find the libsodium ${kind}. Set SODIUM_ROOT to a libsodium ` +
      'SDK directory, or set SODIUM_INCLUDE_DIR and SODIUM_LIB explicitly. ' +
      'A VCPKG_ROOT installation is also supported.'
  )
}

process.stdout.write(
  path.resolve(kind === 'include' ? path.dirname(result) : result)
)

function includeCandidates(searchRoots) {
  return [
    process.env.SODIUM_INCLUDE_DIR,
    ...searchRoots.map((root) => root && path.join(root, 'include'))
  ]
    .filter(Boolean)
    .map((includeDir) => path.join(includeDir, 'sodium.h'))
}

function libraryCandidates(searchRoots, arch) {
  const candidates = [process.env.SODIUM_LIB]

  for (const root of searchRoots.filter(Boolean)) {
    candidates.push(
      path.join(root, 'lib', 'libsodium.lib'),
      path.join(root, 'lib', 'sodium.lib')
    )

    const releaseRoot = path.join(root, archNames[arch], 'Release')
    if (!fs.existsSync(releaseRoot)) continue

    const toolsets = fs
      .readdirSync(releaseRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^v\d+$/.test(entry.name))
      .map((entry) => entry.name)
      .sort((left, right) =>
        right.localeCompare(left, undefined, {
          numeric: true
        })
      )

    for (const toolset of toolsets) {
      candidates.push(
        path.join(releaseRoot, toolset, 'static', 'libsodium.lib')
      )
    }
  }

  return candidates.filter(Boolean)
}

function vcpkgInstalledRoot(root) {
  const triplet =
    process.env.VCPKG_TARGET_TRIPLET ??
    process.env.VCPKG_DEFAULT_TRIPLET ??
    `${vcpkgArchNames[targetArch]}-windows-static`

  return path.join(root, 'installed', triplet)
}

function fail(message) {
  process.stderr.write(`\n@performanc/voice: ${message}\n`)
  process.exit(1)
}
