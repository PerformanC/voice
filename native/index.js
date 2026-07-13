import { createRequire } from 'node:module'

let _native = null
let _encryptionMode = null

const _require = createRequire(import.meta.url)
const mod = _require('./build/Release/voice_send_native.node')

if (mod && typeof mod.createContext === 'function') {
  _native = mod
  _encryptionMode = mod.encryptionMode
} else {
  throw new Error('Incomplete native module')
}

class NativeAudioSender {
  #ctx = null

  constructor(encryptionMode, secretKey, ssrc, sequence, timestamp) {
    if (!_native)
      throw new Error('Native module not available')

    this.#ctx = _native.createContext(
      encryptionMode,
      secretKey,
      ssrc >>> 0,
      (sequence >>> 0) & 0xffff,
      timestamp >>> 0
    )
    if (!this.#ctx)
      throw new Error('Failed to create native context')
  }

  encrypt(audioChunk) {
    if (!this.#ctx) return null

    return _native.encrypt(this.#ctx, audioChunk)
  }

  startLoop(fd, ip, port) {
    if (!this.#ctx) throw new Error('Context destroyed')

    _native.startSendLoop(this.#ctx, fd, ip, port)
  }

  pushAudio(chunk) {
    if (!this.#ctx) return 0

    return _native.pushAudio(this.#ctx, chunk) >>> 0
  }

  signalEndOfStream() {
    if (!this.#ctx) return;

    _native.pushAudio(this.#ctx, null)
  }

  stopLoop() {
    if (!this.#ctx) return;

    _native.stopSendLoop(this.#ctx)
  }

  get sequence() {
    if (!this.#ctx) return 0

    return _native.getSequence(this.#ctx)
  }

  get timestamp() {
    if (!this.#ctx) return 0

    return _native.getTimestamp(this.#ctx)
  }

  get nonce() {
    if (!this.#ctx) return 0

    return _native.getNonce(this.#ctx)
  }

  resetNonce(nonce) {
    if (!this.#ctx) return;

    _native.resetNonce(this.#ctx, nonce >>> 0)
  }

  get queueCount() {
    if (!this.#ctx) return 0

    return _native.getQueueCount(this.#ctx) >>> 0
  }

  get queueDropped() {
    if (!this.#ctx) return 0

    return _native.getQueueDropped(this.#ctx) >>> 0
  }

  get statistics() {
    if (!this.#ctx) return { sent: 0, lost: 0, expected: 0 }

    return _native.getStatistics(this.#ctx)
  }

  /* INFO: Register a JS callback to get periodic stats updates from the loop thread */
  setStatsCallback(fn) {
    if (!this.#ctx) return;

    _native.setStatsCallback(this.#ctx, fn)
  }

  destroy() {
    if (!this.#ctx) return;

    try {
      _native.destroyContext(this.#ctx)
    } catch {}

    this.#ctx = null
  }
}

NativeAudioSender.AES256_GCM = _native ? _encryptionMode.AES256_GCM : 0
NativeAudioSender.XCHACHA20  = _native ? _encryptionMode.XCHACHA20 : 1

export { _native as nativeModule, NativeAudioSender }

export default NativeAudioSender
