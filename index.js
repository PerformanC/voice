import crypto from 'node:crypto'
import dgram from 'node:dgram'
import EventEmitter from 'node:events'
import { performance } from 'node:perf_hooks'
import { PassThrough } from 'node:stream'
import WebSocket from '@performanc/pwsl'
import Sodium from './sodium.js'

let _NativeQueueManager = null
let sharedNativeQueue = null

try {
  const mod = await import('@toddynnn/udpqueue')
  _NativeQueueManager =
    mod?.UdpQueueManager ?? mod?.default?.UdpQueueManager ?? null

  if (!_NativeQueueManager) {
    throw new Error('UdpQueueManager export not found')
  }

  sharedNativeQueue = new _NativeQueueManager(400)
} catch (err) {
  _NativeQueueManager = null
  sharedNativeQueue = null

  console.log(
    '[VoiceUDP] @toddynnn/udpqueue not available — falling back to JS setTimeout pacing'
  )
  console.log(`[VoiceUDP]    Reason: ${err?.message ?? err}`)
}

let MLS = null
try {
  const lib = await import('@snazzah/davey')
  MLS = lib
} catch (err) {
  throw new Error(
    '[DAVE] @snazzah/davey is required for Discord voice E2EE support. ' +
      'Install it or voice connections cannot be created.',
    { cause: err }
  )
}

const MLS_PROTOCOL_VERSION = MLS?.DAVE_PROTOCOL_VERSION ?? 0
if (!MLS_PROTOCOL_VERSION) {
  throw new Error(
    '[DAVE] @snazzah/davey did not expose a supported DAVE_PROTOCOL_VERSION.'
  )
}

const OPUS_SAMPLE_RATE = 48000
const OPUS_FRAME_DURATION = 20
const OPUS_SILENCE_FRAME = Buffer.from([0xf8, 0xff, 0xfe])
const OPUS_SILENCE_FRAME_LENGTH = 3

const TIMESTAMP_INCREMENT = (OPUS_SAMPLE_RATE / 1000) * OPUS_FRAME_DURATION
const OPUS_FRAME_SIZE = (OPUS_SAMPLE_RATE * OPUS_FRAME_DURATION) / 1000
const _MAX_TIMESTAMP = 2 ** 32
const _MAX_SEQUENCE = 2 ** 16

const STABLE_THRESHOLD_MS = 30000

const UDP_KEEPALIVE_BUF = Buffer.alloc(74)
UDP_KEEPALIVE_BUF.writeUInt16BE(1, 0)
UDP_KEEPALIVE_BUF.writeUInt16BE(70, 2)

const DISCORD_CLOSE_CODES = {
  1006: { reconnect: true },
  4014: {},
  4015: { reconnect: true }
}

const ssrcRegistry = new Map()

function _getOrCreateGuildMap(guildId) {
  let guildMap = ssrcRegistry.get(guildId)
  if (!guildMap) {
    guildMap = new Map()
    ssrcRegistry.set(guildId, guildMap)
  }
  return guildMap
}

const PASSTHROUGH_DOWNGRADE_SECS = 10
const PASSTHROUGH_UPGRADE_SECS = 10

const DEFAULT_DECRYPTION_FAILURE_TOLERANCE = 36

const DAVE_OPCODES = {
  PREPARE_TRANSITION: 21,
  EXECUTE_TRANSITION: 22,
  TRANSITION_READY: 23,
  PREPARE_EPOCH: 24,
  EXTERNAL_SENDER: 25,
  KEY_PACKAGE: 26,
  PROPOSALS: 27,
  COMMIT_WELCOME: 28,
  ANNOUNCE_COMMIT: 29,
  WELCOME: 30,
  INVALID_COMMIT_WELCOME: 31
}

function toNodeBuffer(data) {
  if (!data) return null
  if (Buffer.isBuffer(data)) return data
  if (data instanceof ArrayBuffer) return Buffer.from(data)
  if (ArrayBuffer.isView(data))
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  return null
}

function tryParseJSONFromBuffer(buf) {
  if (!buf || buf.length === 0) return null

  let offset = 0
  while (
    offset < buf.length &&
    (buf[offset] === 0x20 ||
      buf[offset] === 0x0a ||
      buf[offset] === 0x0d ||
      buf[offset] === 0x09)
  )
    offset++

  if (offset >= buf.length) return null
  const first = buf[offset]
  if (first !== 0x7b && first !== 0x5b) return null

  try {
    const obj = JSON.parse(buf.subarray(offset).toString('utf8'))
    if (obj && typeof obj === 'object' && typeof obj.op === 'number') return obj
  } catch {}

  return null
}

class VoiceMLS extends EventEmitter {
  constructor(protocolVersion, userId, channelId, MLS, options = {}) {
    super()

    if (!MLS) {
      throw new Error(
        'MLS library (@snazzah/davey) is required but not available'
      )
    }

    this.MLS = MLS
    this.protocolVersion = protocolVersion
    this.userId = userId
    this.channelId = channelId

    this.lastTransitionId = undefined
    this.pendingTransitions = new Map()

    this.downgraded = false

    this.consecutiveFailures = 0
    this.consecutiveEncryptionFailures = 0
    this.reinitializing = false
    this.failureTolerance =
      options.decryptionFailureTolerance ?? DEFAULT_DECRYPTION_FAILURE_TOLERANCE

    this.session = null

    this.externalSender = null
    this.externalSenderSet = false

    this._pendingKeyPackage = null

    this._pendingDowngrade = false

    this.reinit({ emitKeyPackage: false })
  }

  get transitioning() {
    return this.pendingTransitions.size > 0
  }

  reinit({ emitKeyPackage } = { emitKeyPackage: true }) {
    this.pendingTransitions.clear()
    this._pendingDowngrade = false
    this.externalSenderSet = false
    this.consecutiveFailures = 0
    this.consecutiveEncryptionFailures = 0

    if (this.protocolVersion > 0) {
      if (this.session) {
        this.session.reinit(this.protocolVersion, this.userId, this.channelId)
      } else {
        this.session = new this.MLS.DAVESession(
          this.protocolVersion,
          this.userId,
          this.channelId
        )
      }

      if (this.externalSender) {
        try {
          this.session.setExternalSender(this.externalSender)
          this.externalSenderSet = true
        } catch {}
      }

      const keyPackage = this.session.getSerializedKeyPackage()
      this._pendingKeyPackage = keyPackage

      if (emitKeyPackage) this.emit('keyPackage', keyPackage)
      return
    }

    if (this.session) {
      try {
        this.session.reset()
      } catch {}
      try {
        this.session.setPassthroughMode(true, PASSTHROUGH_UPGRADE_SECS)
      } catch {}
    }
  }

  flushKeyPackage() {
    if (!this._pendingKeyPackage) return null
    this.emit('keyPackage', this._pendingKeyPackage)
    return this._pendingKeyPackage
  }

  setExternalSender(externalSender) {
    if (!this.session) throw new Error('No session available')

    this.externalSender = Buffer.from(externalSender)
    this.session.setExternalSender(externalSender)
    this.externalSenderSet = true
  }

  prepareTransition(data) {
    this.pendingTransitions.set(data.transition_id, data.protocol_version)

    if (data.transition_id === 0) {
      this.executeTransition(0)
      return false
    }

    if (data.protocol_version === 0) {
      this._pendingDowngrade = true
      try {
        this.session?.setPassthroughMode(true, PASSTHROUGH_DOWNGRADE_SECS)
      } catch {}
    }
    return true
  }

  executeTransition(transitionId) {
    const nextVersion = this.pendingTransitions.get(transitionId)
    if (nextVersion === undefined) return false

    const oldVersion = this.protocolVersion
    this.protocolVersion = nextVersion
    this._pendingDowngrade = false

    if (oldVersion !== this.protocolVersion && this.protocolVersion === 0) {
      this.downgraded = true
    } else if (
      transitionId > 0 &&
      this.downgraded &&
      this.protocolVersion > 0
    ) {
      this.downgraded = false
      try {
        this.session?.setPassthroughMode(true, PASSTHROUGH_UPGRADE_SECS)
      } catch {}
    }

    this.pendingTransitions.delete(transitionId)

    this.reinitializing = false
    this.consecutiveFailures = 0
    this.consecutiveEncryptionFailures = 0
    this.lastTransitionId = transitionId

    return true
  }

  prepareEpoch(data) {
    if (data.epoch === 1) {
      this.protocolVersion = data.protocol_version
      this.downgraded = false
      this._pendingDowngrade = false
      this.reinit({ emitKeyPackage: true })
    }
  }

  recoverFromInvalidTransition(transitionId) {
    if (this.reinitializing) return

    this.reinitializing = true
    this.consecutiveFailures = 0
    this.consecutiveEncryptionFailures = 0
    this._pendingDowngrade = false
    this.pendingTransitions.clear()

    this.emit('invalidateTransition', transitionId)
    this.reinit({ emitKeyPackage: true })
    this.reinitializing = false
  }

  processProposals(payload, connectedclients) {
    if (!this.session) throw new Error('No session available')

    const optype = payload.readUInt8(0)

    const { commit, welcome } = this.session.processProposals(
      optype,
      payload.subarray(1),
      connectedclients
    )

    if (!commit) return null
    return welcome ? Buffer.concat([commit, welcome]) : commit
  }

  _processServerTransition(serverPayload, method) {
    if (!this.session) throw new Error('No session available')

    const transitionId = serverPayload.readUInt16BE(0)

    try {
      this.session[method](serverPayload.subarray(2))

      if (transitionId !== 0 && !this.pendingTransitions.has(transitionId)) {
        this.pendingTransitions.set(transitionId, this.protocolVersion)
      }

      if (transitionId === 0) {
        this.reinitializing = false
        this.lastTransitionId = 0
      }

      return { transitionId, success: true }
    } catch {
      this.recoverFromInvalidTransition(transitionId)
      return { transitionId, success: false }
    }
  }

  processCommit(serverPayload) {
    return this._processServerTransition(serverPayload, 'processCommit')
  }

  processWelcome(serverPayload) {
    return this._processServerTransition(serverPayload, 'processWelcome')
  }

  encrypt(packet) {
    if (
      packet.length === 3 &&
      packet[0] === 0xf8 &&
      packet[1] === 0xff &&
      packet[2] === 0xfe
    )
      return packet
    if (this._pendingDowngrade) return packet
    if (this.protocolVersion === 0) return packet
    if (!this.session?.ready) return null

    try {
      const encrypted = this.session.encryptOpus(packet)
      this.consecutiveEncryptionFailures = 0
      return encrypted
    } catch {
      if (!this.reinitializing && !this.transitioning) {
        this.consecutiveEncryptionFailures++
        if (this.consecutiveEncryptionFailures > this.failureTolerance) {
          this.recoverFromInvalidTransition(this.lastTransitionId ?? 0)
        }
      }
      return null
    }
  }

  decrypt(packet, userId) {
    if (
      packet.length === OPUS_SILENCE_FRAME_LENGTH &&
      packet[0] === 0xf8 &&
      packet[1] === 0xff &&
      packet[2] === 0xfe
    ) {
      return packet
    }

    if (!this.session?.ready) {
      if (
        this.protocolVersion !== 0 &&
        !this.transitioning &&
        !this._pendingDowngrade
      ) {
        return null
      }
      return packet
    }

    const canTry =
      this.protocolVersion !== 0 || this.session.canPassthrough(userId)

    if (!canTry) return packet

    try {
      const buffer = this.session.decrypt(
        userId,
        this.MLS.MediaType.AUDIO,
        packet
      )
      this.consecutiveFailures = 0
      return buffer
    } catch {
      if (!this.reinitializing && !this.transitioning) {
        this.consecutiveFailures++
        if (this.consecutiveFailures > this.failureTolerance) {
          this.recoverFromInvalidTransition(this.lastTransitionId ?? 0)
        }
      }

      return null
    }
  }

  destroy() {
    this.pendingTransitions.clear()
    try {
      this.session?.reset()
    } catch {}
  }
}

class Connection extends EventEmitter {
  constructor(obj) {
    super()

    this.guildId = obj.guildId
    this.userId = obj.userId
    this.channelId = obj.channelId ?? obj.channel_id ?? null
    this.encryption = obj.encryption

    this.ws = null

    this.state = {
      status: 'disconnected',
      reason: null,
      code: null,
      closeReason: null
    }
    this.playerState = { status: 'idle', reason: null }

    this.sessionId = null
    this.voiceServer = null

    this.hbInterval = null
    this.hbIntervalMissed = 0
    this.udpKeepAliveInterval = null
    this.udpInfo = null
    this.udp = null

    this.ping = -1
    this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }

    this.player = {
      sequence: crypto.randomInt(_MAX_SEQUENCE),
      timestamp: crypto.randomInt(_MAX_TIMESTAMP) >>> 0,
      nextPacket: 0,
      lastPacketTime: null
    }

    this._reconnectSuccessCount = 0
    this._lastStableTime = 0

    this.nonce = 0
    this.nonceBuffer = Connection._createNonceBuffer(this.encryption)

    this._recvNonce24 = Buffer.alloc(24)
    this._recvNonce12 = this._recvNonce24.subarray(0, 12)
    this._sendBuffer = Buffer.allocUnsafe(1232)

    this._onUdpSend = (error) => {
      if (error) this.statistics.packetsLost++
      else this.statistics.packetsSent++
      this.statistics.packetsExpected++
    }

    this.playTimeout = null
    this.challengeTimeout = null
    this.connectTimeout = null
    this.audioStream = null

    this.lastSequence = -1

    this.mlsSession = null
    this.mlsProtocolVersion = MLS_PROTOCOL_VERSION
    this.pendingExternalSender = null
    this.lastExternalSender = null
    this.pendingProposals = []
    this.connectedUserIds = new Set()
    this._keyPackageSent = false
    this._silenceKeepaliveTimer = null

    this._nativeQueueManager = obj.nativeQueueManager ?? null
    this.useSharedQueue = obj.useSharedQueue ?? true
    this._nativeQueueKey = null
    this._privateQueueManager = false

    if (
      !this._nativeQueueManager &&
      _NativeQueueManager &&
      !this.useSharedQueue
    ) {
      try {
        this._nativeQueueManager = new _NativeQueueManager(400)
        this._privateQueueManager = true
      } catch {
        this._nativeQueueManager = sharedNativeQueue
      }
    }

    if (!this._nativeQueueManager) {
      this._nativeQueueManager = sharedNativeQueue
    }

    this._queueHasSendNow =
      !!this._nativeQueueManager &&
      typeof this._nativeQueueManager.sendNow === 'function'

    this.ssrcs = new Map()
    this._userIdToSSRCs = new Map()

    this._reconnectCount = 0
    this._lastReconnectTime = 0
    this._reconnectCircuitBreakerThreshold = 5
    this._reconnectCircuitBreakerWindowMs = 60000
    this._loggedMissingSecretKey = false

    this.stuckTimeout = 2000

    this._boundMarkAsStoppable = () => this._markAsStoppable()
    this._boundPacketInterval = this._packetInterval.bind(this)
  }

  static _createNonceBuffer(encryption) {
    return encryption === 'aead_aes256_gcm_rtpsize'
      ? Buffer.alloc(12)
      : Buffer.alloc(24)
  }

  _registerSSRC(ssrc) {
    _getOrCreateGuildMap(this.guildId).set(ssrc, this)
  }

  _unregisterSSRC(ssrc) {
    const guildMap = ssrcRegistry.get(this.guildId)
    if (guildMap && guildMap.get(ssrc) === this) {
      guildMap.delete(ssrc)
      if (guildMap.size === 0) ssrcRegistry.delete(this.guildId)
    }
  }

  _updateState(state) {
    this.emit('stateChange', this.state, state)
    this.state.status = state.status ?? null
    this.state.reason = state.reason ?? null
    this.state.code = state.code ?? null
    this.state.closeReason = state.closeReason ?? null
  }

  _updatePlayerState(state) {
    this.emit('playerStateChange', this.playerState, state)
    this.playerState.status = state.status ?? null
    this.playerState.reason = state.reason ?? null
  }

  _wsSendJSON(op, d) {
    if (!this.ws) return
    this.ws.send(JSON.stringify({ op, d }))
  }

  _wsSendBinary(opcode, payload) {
    const ws = this.ws
    if (!ws) return

    const p = payload
      ? Buffer.isBuffer(payload)
        ? payload
        : Buffer.from(payload)
      : null

    const frame = Buffer.allocUnsafe(1 + (p?.length ?? 0))
    frame[0] = opcode
    if (p?.length) p.copy(frame, 1)
    ws.send(frame)
  }

  _parseServerBinaryMessage(buf) {
    if (!buf || buf.length < 3) return null

    this.lastSequence = buf.readUInt16BE(0)
    const opcode = buf.readUInt8(2)
    const payload = buf.subarray(3)

    return { opcode, payload }
  }

  _initMLSSessionIfNeeded(protocolVersionHint) {
    if (!MLS) return
    if (!this.channelId) return
    if (this.mlsSession) return

    const initialVersion =
      typeof protocolVersionHint === 'number'
        ? protocolVersionHint
        : this.mlsProtocolVersion

    try {
      this.mlsSession = new VoiceMLS(
        initialVersion,
        this.userId,
        this.channelId,
        MLS
      )

      this.mlsSession.on('error', (err) => this.emit('error', err))

      this.mlsSession.on('keyPackage', (keyPackage) => {
        this._wsSendBinary(DAVE_OPCODES.KEY_PACKAGE, keyPackage)
      })

      this.mlsSession.on('invalidateTransition', (transitionId) => {
        this._wsSendJSON(DAVE_OPCODES.INVALID_COMMIT_WELCOME, {
          transition_id: transitionId
        })
      })

      const ext = this.lastExternalSender ?? this.pendingExternalSender
      if (ext) {
        try {
          this.mlsSession.setExternalSender(ext)
          this.pendingExternalSender = null
        } catch (e) {
          this.emit(
            'error',
            new Error(`[DAVE] Failed to apply external sender: ${e.message}`)
          )
        }
      }

      this.mlsSession.flushKeyPackage()
      this._drainBufferedProposals()
      this._keyPackageSent = true
    } catch (error) {
      this.emit(
        'error',
        new Error(`[DAVE] Failed to initialize session: ${error.message}`)
      )
    }
  }

  _ensureKeyPackageSent() {
    if (!MLS) return
    if (this._keyPackageSent) return

    if (!this.mlsSession) {
      this._initMLSSessionIfNeeded(this.mlsProtocolVersion)
    }

    if (!this.mlsSession) return

    try {
      const kp =
        this.mlsSession._pendingKeyPackage ??
        this.mlsSession.session?.getSerializedKeyPackage?.()

      if (kp && this.ws) {
        this._wsSendBinary(DAVE_OPCODES.KEY_PACKAGE, kp)
        this._keyPackageSent = true
      }
    } catch (e) {
      this.emit(
        'error',
        new Error(`[DAVE] Failed to send key package: ${e.message}`)
      )
    }
  }

  _drainBufferedProposals() {
    if (!this.mlsSession) return
    if (!this.mlsSession.externalSenderSet) return
    if (this.pendingProposals.length === 0) return

    const connected = Array.from(this.connectedUserIds)
    const proposals = this.pendingProposals
    this.pendingProposals = []

    for (const payload of proposals) {
      try {
        const response = this.mlsSession.processProposals(payload, connected)
        if (response) {
          this._wsSendBinary(DAVE_OPCODES.COMMIT_WELCOME, response)
        }
      } catch (e) {
        this.emit(
          'error',
          new Error(`[DAVE] processProposals failed: ${e.message}`)
        )

        this.pendingProposals.length = 0

        try {
          const tid = this.mlsSession?.lastTransitionId ?? 0
          this.mlsSession?.recoverFromInvalidTransition(tid)
        } catch (e2) {
          this.emit(
            'error',
            new Error(
              `[DAVE] recovery from failed proposals failed: ${e2.message}`
            )
          )
        }
      }
    }
  }

  udpSend(data, cb) {
    if (!this.udp || !this.udpInfo) return

    if (!cb) {
      cb = (error) => {
        if (error) this.emit('error', error)
      }
    }

    this.udp.send(data, this.udpInfo.port, this.udpInfo.ip, cb)
  }

  _setSpeaking(value) {
    if (!this.ws || !this.udpInfo) return
    this._wsSendJSON(5, { speaking: value, delay: 0, ssrc: this.udpInfo.ssrc })
  }

  _ipDiscovery(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const udp = this.udp
      const udpInfo = this.udpInfo

      if (!udp || !udpInfo) {
        reject(new Error('UDP socket not ready for IP discovery'))
        return
      }

      let settled = false
      let timer = null

      const cleanup = () => {
        if (timer) {
          clearTimeout(timer)
          timer = null
        }
        udp.off('message', onMessage)
        udp.off('error', onError)
        udp.off('close', onClose)
      }

      const finish = (fn, value) => {
        if (settled) return
        settled = true
        cleanup()
        fn(value)
      }

      const onMessage = (message) => {
        if (!message || message.length < 10) return

        const type = message.readUInt16BE(0)
        if (type !== 2) return

        const zeroIndex = message.indexOf(0, 8)
        if (zeroIndex === -1) return
        if (message.length < 2) return

        finish(resolve, {
          ip: message.subarray(8, zeroIndex).toString('utf8'),
          port: message.readUInt16BE(message.length - 2)
        })
      }

      const onError = (err) => finish(reject, err)
      const onClose = () =>
        finish(reject, new Error('UDP closed during IP discovery'))

      timer = setTimeout(() => {
        finish(reject, new Error(`IP discovery timed out after ${timeoutMs}ms`))
      }, timeoutMs)

      udp.on('message', onMessage)
      udp.on('error', onError)
      udp.on('close', onClose)

      const discoveryBuffer = Buffer.alloc(74)
      discoveryBuffer.writeUInt16BE(1, 0)
      discoveryBuffer.writeUInt16BE(70, 2)
      discoveryBuffer.writeUInt32BE(udpInfo.ssrc, 4)

      udp.send(discoveryBuffer, udpInfo.port, udpInfo.ip, (error) => {
        if (error) finish(reject, error)
      })
    })
  }

  _setupNativeQueue(ip, port) {
    if (!this._nativeQueueManager) return

    const hasCreate = typeof this._nativeQueueManager.createQueue === 'function'
    const hasUpdate =
      typeof this._nativeQueueManager.updateQueueTarget === 'function'
    const hasDelete = typeof this._nativeQueueManager.deleteQueue === 'function'

    if (!hasCreate) {
      this._nativeQueueKey = null
      return
    }

    if (this._nativeQueueKey !== null && hasUpdate) {
      try {
        this._nativeQueueManager.updateQueueTarget(
          this._nativeQueueKey,
          ip,
          port
        )
        return
      } catch {
        if (hasDelete) {
          try {
            this._nativeQueueManager.deleteQueue(this._nativeQueueKey)
          } catch {}
        }

        this._nativeQueueKey = null
      }
    }

    if (this._nativeQueueKey !== null && !hasUpdate && hasDelete) {
      try {
        this._nativeQueueManager.deleteQueue(this._nativeQueueKey)
      } catch {}
      this._nativeQueueKey = null
    }

    try {
      this._nativeQueueKey = this._nativeQueueManager.createQueue(ip, port, 400)
    } catch {
      this._nativeQueueKey = null
    }
  }

  _sendPacketViaQueue(packet) {
    if (this._nativeQueueKey === null || !this._nativeQueueManager) {
      return false
    }

    const queued = this._nativeQueueManager.pushPacket(
      this._nativeQueueKey,
      Buffer.from(packet)
    )

    this.player.lastPacketTime = performance.now()
    if (queued) {
      this.statistics.packetsSent++
    } else {
      if (this._queueHasSendNow) {
        const sent = this._nativeQueueManager.sendNow(
          this._nativeQueueKey,
          packet
        )
        if (sent) this.statistics.packetsSent++
        else this.statistics.packetsLost++
      } else {
        this.statistics.packetsLost++
      }
    }
    this.statistics.packetsExpected++

    return true
  }

  _clearNativeQueue() {
    if (this._nativeQueueKey === null || !this._nativeQueueManager) return
    if (typeof this._nativeQueueManager.clearQueue !== 'function') return

    try {
      this._nativeQueueManager.clearQueue(this._nativeQueueKey)
    } catch {}
  }

  _destroyNativeQueue() {
    if (this._nativeQueueKey === null || !this._nativeQueueManager) return
    if (typeof this._nativeQueueManager.deleteQueue !== 'function') {
      this._nativeQueueKey = null
      return
    }

    try {
      this._nativeQueueManager.deleteQueue(this._nativeQueueKey)
    } catch {}

    this._nativeQueueKey = null
  }

  _startSilenceKeepalive() {
    if (this._silenceKeepaliveTimer) return

    // https://github.com/Snazzah/davey/blob/master/docs/USAGE.md#handling-voice-packets
    // Silence frames are already handled by the MLS session
    if (this.mlsSession && this.mlsSession.protocolVersion > 0) {
      this._setSpeaking(1 << 0)
      return
    }

    this._setSpeaking(1 << 0)

    this._silenceKeepaliveTimer = setInterval(() => {
      if (!this.udpInfo?.secretKey || this.connectedUserIds.size > 0) {
        this._stopSilenceKeepalive()
        return
      }
      this.sendAudioChunk(OPUS_SILENCE_FRAME)
    }, 5000)
  }

  _stopSilenceKeepalive() {
    if (!this._silenceKeepaliveTimer) return
    clearInterval(this._silenceKeepaliveTimer)
    this._silenceKeepaliveTimer = null
    this._setSpeaking(0)
  }

  connect(cb, reconnection) {
    if (this.ws) {
      this._destroyConnection(1000, 'Normal close')
      this._updateState({
        status: 'disconnected',
        reason: 'closed',
        code: 4014,
        closeReason: 'Disconnected.'
      })
      this._updatePlayerState({ status: 'idle', reason: 'destroyed' })
    }

    if (reconnection) {
      const now = Date.now()
      if (
        now - this._lastReconnectTime <
        this._reconnectCircuitBreakerWindowMs
      ) {
        this._reconnectCount++
      } else {
        this._reconnectCount = 0
      }
      this._lastReconnectTime = now

      if (this._reconnectCount >= this._reconnectCircuitBreakerThreshold) {
        const err = new Error(
          `Reconnection circuit breaker triggered (${this._reconnectCount} reconnects). ` +
            `Stopping voice connection for guild ${this.guildId}.`
        )
        this.emit('error', err)
        this._destroy(
          {
            status: 'disconnected',
            reason: 'reconnect_circuit_breaker',
            code: 4015,
            closeReason: 'Too many reconnections'
          },
          false
        )
        return
      }
    }

    this._updateState({ status: 'connecting' })

    if (this.connectTimeout) clearTimeout(this.connectTimeout)
    this.connectTimeout = setTimeout(() => {
      if (this.ws) {
        this.ws.close(4009, 'Connection timed out')
        this.emit('error', new Error('Voice connection timed out'))
      }
    }, 15000)

    this.ws = new WebSocket(`wss://${this.voiceServer.endpoint}/?v=8`, {
      headers: {
        'User-Agent': 'DiscordBot (https://github.com/PerformanC/voice, 2.2.0)'
      }
    })

    this.ws.binaryType = 'arraybuffer'

    this.ws.on('open', () => {
      if (this.connectTimeout) {
        clearTimeout(this.connectTimeout)
        this.connectTimeout = null
      }

      if (reconnection) {
        this._wsSendJSON(7, {
          server_id: this.guildId,
          session_id: this.sessionId,
          token: this.voiceServer.token,
          seq_ack: this.lastSequence
        })
      } else {
        this._wsSendJSON(0, {
          server_id: this.guildId,
          user_id: this.userId,
          session_id: this.sessionId,
          token: this.voiceServer.token,
          max_dave_protocol_version: this.channelId
            ? this.mlsProtocolVersion
            : 0
        })
      }
    })

    this.ws.on('message', (data) => {
      if (typeof data === 'string') {
        let payload
        try {
          payload = JSON.parse(data)
        } catch {
          return
        }

        if (typeof payload.seq === 'number') this.lastSequence = payload.seq
        return this._handleJSON(payload, cb).catch((err) =>
          this.emit('error', err)
        )
      }

      const buf = toNodeBuffer(data)
      if (!buf) return

      const maybeJSON = tryParseJSONFromBuffer(buf)
      if (maybeJSON) {
        if (typeof maybeJSON.seq === 'number') this.lastSequence = maybeJSON.seq
        return this._handleJSON(maybeJSON, cb).catch((err) =>
          this.emit('error', err)
        )
      }

      const parsed = this._parseServerBinaryMessage(buf)
      if (!parsed) return

      const { opcode, payload } = parsed

      switch (opcode) {
        case DAVE_OPCODES.EXTERNAL_SENDER: {
          this.lastExternalSender = Buffer.from(payload)

          if (this.mlsSession) {
            try {
              this.mlsSession.setExternalSender(payload)
            } catch (e) {
              this.emit(
                'error',
                new Error(`[DAVE] Failed to set external sender: ${e.message}`)
              )
            }
            this._drainBufferedProposals()
          } else {
            this.pendingExternalSender = Buffer.from(payload)
          }
          break
        }

        case DAVE_OPCODES.PROPOSALS: {
          if (!this.mlsSession) {
            this._initMLSSessionIfNeeded(this.mlsProtocolVersion)
          }

          if (!this.mlsSession) break

          if (!this.mlsSession.externalSenderSet) {
            if (this.pendingProposals.length >= 50) {
              this.pendingProposals.shift()
            }
            this.pendingProposals.push(payload)
            break
          }

          try {
            const connected = Array.from(this.connectedUserIds)
            const response = this.mlsSession.processProposals(
              payload,
              connected
            )
            if (response) {
              this._wsSendBinary(DAVE_OPCODES.COMMIT_WELCOME, response)
            }
          } catch (e) {
            this.emit(
              'error',
              new Error(`[DAVE] Failed to process proposals: ${e.message}`)
            )
          }

          break
        }

        case DAVE_OPCODES.ANNOUNCE_COMMIT: {
          if (!this.mlsSession) break

          try {
            const result = this.mlsSession.processCommit(payload)
            if (result.success && result.transitionId !== 0) {
              this._wsSendJSON(DAVE_OPCODES.TRANSITION_READY, {
                transition_id: result.transitionId
              })
            }
          } catch (e) {
            this.emit(
              'error',
              new Error(`[DAVE] Failed to process commit: ${e.message}`)
            )
          }
          break
        }

        case DAVE_OPCODES.WELCOME: {
          if (!this.mlsSession) {
            this._initMLSSessionIfNeeded(this.mlsProtocolVersion)
          }
          if (!this.mlsSession) break

          try {
            const result = this.mlsSession.processWelcome(payload)
            if (result.success && result.transitionId !== 0) {
              this._wsSendJSON(DAVE_OPCODES.TRANSITION_READY, {
                transition_id: result.transitionId
              })
            }
          } catch (e) {
            this.emit(
              'error',
              new Error(`[DAVE] Failed to process welcome: ${e.message}`)
            )
          }
          break
        }
      }
    })

    this.ws.on('close', (code, reason) => {
      if (!this.ws) return

      const closeCode = DISCORD_CLOSE_CODES[code]

      if (this.connectTimeout) {
        clearTimeout(this.connectTimeout)
        this.connectTimeout = null
      }

      if (closeCode?.reconnect) {
        this.emit(
          'error',
          new Error(
            `Voice WS closed with reconnect code ${code} (${reason}). ` +
              `Reconnect attempt ${this._reconnectCount + 1}/${this._reconnectCircuitBreakerThreshold}.`
          )
        )

        const savedUdp = this.udp
        const savedUdpKeepalive = this.udpKeepAliveInterval
        const savedUdpInfo = this.udpInfo
        this._destroyConnection(code, reason)
        if (savedUdp && !this.udp) {
          this.udp = savedUdp
          this.udpInfo = savedUdpInfo
          if (savedUdpKeepalive) {
            clearInterval(savedUdpKeepalive)
            this.udpKeepAliveInterval = setInterval(() => {
              if (!this.udp || !this.udpInfo) return
              UDP_KEEPALIVE_BUF.writeUInt32BE(this.udpInfo.ssrc, 4)
              this.udpSend(UDP_KEEPALIVE_BUF)
            }, 10000)
          }
        }
        this._updatePlayerState({ status: 'idle', reason: 'reconnecting' })

        this.connect(() => {
          if (this.audioStream) this.unpause('reconnected')
        }, true)
      } else {
        this._destroy(
          {
            status: 'disconnected',
            reason: 'closed',
            code,
            closeReason: reason
          },
          false
        )
      }
    })

    this.ws.on('error', (error) => this.emit('error', error))
  }

  _cleanupSSRCsForUserId(userId) {
    const uid = String(userId)
    const ssrcSet = this._userIdToSSRCs.get(uid)
    if (!ssrcSet) return

    for (const ssrc of ssrcSet) {
      const entry = this.ssrcs.get(ssrc)
      if (entry) {
        try {
          if (
            entry.stream &&
            !entry.stream.destroyed &&
            !entry.stream.writableEnded
          ) {
            entry.stream.end()
          }
        } catch {}
        this.ssrcs.delete(ssrc)
        this._unregisterSSRC(ssrc)
      }
    }
    this._userIdToSSRCs.delete(uid)
  }

  async _handleJSON(payload, cb) {
    switch (payload.op) {
      case 2: {
        this.udpInfo = {
          ssrc: payload.d.ssrc,
          ip: payload.d.ip,
          port: payload.d.port,
          secretKey: null
        }

        this.udp = dgram.createSocket('udp4')

        this.udp.on('message', (data) => {
          if (data.length <= 12) return

          const rtpVersion = data[0] >> 6
          if (rtpVersion !== 2) return

          const payloadType = data[1] & 0x7f
          if (payloadType !== 0x78) return

          const ssrc = data.readUInt32BE(8)
          const userData = this.ssrcs.get(ssrc)
          if (!userData || !this.udpInfo?.secretKey) return

          const hasPadding = !!(data[0] & 0b100000)
          const hasExtension = !!(data[0] & 0b10000)
          const cc = data[0] & 0b1111

          const nonce =
            this.encryption === 'aead_aes256_gcm_rtpsize'
              ? this._recvNonce12
              : this._recvNonce24

          nonce.fill(0)
          data.copy(nonce, 0, data.length - 4, data.length)

          let headerSize = 12 + cc * 4
          let extensionLengthInWords = 0
          if (data.length < headerSize) return

          if (hasExtension) {
            if (data.length < headerSize + 4) return
            extensionLengthInWords = data.readUInt16BE(headerSize + 2)
            headerSize += 4
          }

          const header = data.subarray(0, headerSize)

          let decryptedPacket

          if (this.encryption === 'aead_aes256_gcm_rtpsize') {
            const trailerLength = 16 + 4
            if (data.length < headerSize + trailerLength) return

            const encrypted = data.subarray(
              headerSize,
              data.length - trailerLength
            )
            const authTag = data.subarray(
              data.length - trailerLength,
              data.length - 4
            )

            try {
              const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                this.udpInfo.secretKey,
                nonce
              )
              decipher.setAAD(header)
              decipher.setAuthTag(authTag)

              const u = decipher.update(encrypted)
              const f = decipher.final()

              decryptedPacket = f.length ? Buffer.concat([u, f]) : u
            } catch (e) {
              this.emit(
                'error',
                new Error(`Failed to decrypt AES-256-GCM packet: ${e.message}`)
              )
              return
            }
          } else if (this.encryption === 'aead_xchacha20_poly1305_rtpsize') {
            if (data.length < headerSize + 4) return

            const encrypted = data.subarray(headerSize, data.length - 4)
            try {
              decryptedPacket =
                Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                  encrypted,
                  header,
                  nonce,
                  this.udpInfo.secretKey
                )
            } catch (e) {
              this.emit(
                'error',
                new Error(
                  `Failed to decrypt XChaCha20-Poly1305 packet: ${e.message}`
                )
              )
              return
            }
          } else {
            return
          }

          if (!decryptedPacket || decryptedPacket.length === 0) return

          if (hasPadding) {
            const paddingAmount = decryptedPacket.readUInt8(
              decryptedPacket.length - 1
            )
            if (paddingAmount > 0) {
              if (paddingAmount >= decryptedPacket.length) return
              decryptedPacket = decryptedPacket.subarray(
                0,
                decryptedPacket.length - paddingAmount
              )
            }
          }

          const extensionDataLength = extensionLengthInWords * 4
          if (hasExtension) {
            if (extensionDataLength > decryptedPacket.length) return
            decryptedPacket = decryptedPacket.subarray(extensionDataLength)
          }

          let packet = decryptedPacket

          if (this.mlsSession && userData.userId) {
            if (
              !this.mlsSession.session?.ready &&
              this.mlsSession.protocolVersion !== 0
            ) {
              return
            }

            const decrypted = this.mlsSession.decrypt(packet, userData.userId)
            if (decrypted !== null) packet = decrypted
            else return
          }

          if (
            packet.length === 3 &&
            packet[0] === 0xf8 &&
            packet[1] === 0xff &&
            packet[2] === 0xfe
          ) {
            if (userData.stream.destroyed || userData.stream.writableEnded)
              return
            this.emit('speakEnd', userData.userId, ssrc)
            userData.stream.end()
          } else {
            if (
              userData.stream.readableEnded ||
              userData.stream.writableEnded ||
              userData.stream.destroyed
            ) {
              userData.stream = new PassThrough()
              this.emit('speakStart', userData.userId, ssrc)
            }
            try {
              userData.stream.write(packet)
            } catch {
              userData.stream = new PassThrough()
              this.emit('speakStart', userData.userId, ssrc)
              userData.stream.write(packet)
            }
          }
        })

        this.udp.on('error', (error) => this.emit('error', error))

        this.udp.on('close', () => {
          if (!this.ws) return
          this.emit(
            'error',
            new Error(
              'UDP socket closed unexpectedly while WebSocket still open'
            )
          )
          this._destroy({ status: 'disconnected', reason: 'udp_closed' })
        })

        let serverInfo
        try {
          serverInfo = await this._ipDiscovery()
        } catch (error) {
          this.emit('error', new Error(`IP discovery failed: ${error.message}`))
          this._destroy(
            { status: 'disconnected', reason: 'ip_discovery_failed' },
            false
          )
          return
        }

        if (
          !serverInfo ||
          typeof serverInfo.ip !== 'string' ||
          serverInfo.ip.length === 0 ||
          typeof serverInfo.port !== 'number' ||
          serverInfo.port <= 0
        ) {
          this.emit(
            'error',
            new Error(
              `IP discovery returned invalid data: ${JSON.stringify(serverInfo)}`
            )
          )
          this._destroy(
            { status: 'disconnected', reason: 'ip_discovery_invalid' },
            false
          )
          return
        }

        this._setupNativeQueue(this.udpInfo.ip, this.udpInfo.port)

        if (this.udpKeepAliveInterval) clearInterval(this.udpKeepAliveInterval)
        this.udpKeepAliveInterval = setInterval(() => {
          if (!this.udp || !this.udpInfo) return

          UDP_KEEPALIVE_BUF.writeUInt32BE(this.udpInfo.ssrc, 4)

          this.udpSend(UDP_KEEPALIVE_BUF)
        }, 10000)

        this._wsSendJSON(1, {
          protocol: 'udp',
          data: {
            address: serverInfo.ip,
            port: serverInfo.port,
            mode: this.encryption
          }
        })

        break
      }

      case 4: {
        if (Date.now() - this._lastReconnectTime > STABLE_THRESHOLD_MS) {
          this._reconnectCount = 0
          this._lastReconnectTime = 0
        }

        if (payload.d.mode && payload.d.mode !== this.encryption) {
          this.encryption = payload.d.mode
          this.nonceBuffer = Connection._createNonceBuffer(this.encryption)
        }

        this.udpInfo.secretKey = Buffer.from(payload.d.secret_key)

        if (!this.udpInfo.secretKey || this.udpInfo.secretKey.length === 0) {
          this.emit(
            'error',
            new Error('Select protocol ACK (op 4) returned empty secret_key')
          )
        }

        if (cb) cb()

        this._updateState({ status: 'connected' })
        this._updatePlayerState({ status: 'idle', reason: 'connected' })

        const serverVersion = payload.d.dave_protocol_version ?? 0

        this.mlsProtocolVersion = Math.min(serverVersion, MLS_PROTOCOL_VERSION)
        this._keyPackageSent = false

        if (serverVersion > 0) {
          this._initMLSSessionIfNeeded(this.mlsProtocolVersion)
          this._ensureKeyPackageSent()
        } else if (this.mlsSession) {
          this.mlsSession.protocolVersion = 0
          this.mlsSession.reinit({ emitKeyPackage: false })
        }

        break
      }

      case 5: {
        const ssrcVal = payload.d.ssrc
        const uid5 = String(payload.d.user_id)
        this.ssrcs.set(ssrcVal, {
          userId: uid5,
          stream: this.ssrcs.get(ssrcVal)?.stream ?? new PassThrough()
        })
        this._registerSSRC(ssrcVal)
        let ssrcSet = this._userIdToSSRCs.get(uid5)
        if (!ssrcSet) {
          ssrcSet = new Set()
          this._userIdToSSRCs.set(uid5, ssrcSet)
        }
        ssrcSet.add(ssrcVal)
        this.emit('speakStart', uid5, ssrcVal)
        break
      }

      case 6: {
        this.hbIntervalMissed = 0
        this.ping = Date.now() - payload.d.t
        break
      }

      case 8: {
        if (this.hbInterval) clearInterval(this.hbInterval)

        this.hbInterval = setInterval(() => {
          if (this.hbIntervalMissed >= 3) {
            if (this.hbInterval) clearInterval(this.hbInterval)
            this.hbInterval = null

            if (this.ws) this.ws.close(4015, 'Heartbeat timeout')
            return
          }

          this.hbIntervalMissed++
          this._wsSendJSON(3, { t: Date.now(), seq_ack: this.lastSequence })
        }, payload.d.heartbeat_interval)

        break
      }

      case 9: {
        if (Date.now() - this._lastReconnectTime > STABLE_THRESHOLD_MS) {
          this._reconnectCount = 0
          this._lastReconnectTime = 0
        }
        if (cb) cb()
        this._updateState({ status: 'connected' })
        this._updatePlayerState({ status: 'idle', reason: 'reconnected' })
        break
      }

      case 11: {
        const ids = payload.d?.user_ids ?? []
        for (const id of ids) {
          if (String(id) !== this.userId) this.connectedUserIds.add(String(id))
        }
        if (this.connectedUserIds.size > 0 && this.ws?.readyState === 1) {
          this._stopSilenceKeepalive()
          this.emit('channelNotEmpty')
        }
        break
      }

      case 13: {
        const id = payload.d?.user_id
        if (id) {
          const uid = String(id)
          this.connectedUserIds.delete(uid)
          this._cleanupSSRCsForUserId(uid)
        }
        if (this.connectedUserIds.size === 0) {
          this._startSilenceKeepalive()
          this.emit('channelEmpty')
        }
        break
      }

      case DAVE_OPCODES.PREPARE_TRANSITION: {
        if (payload.d?.protocol_version > 0 && !this.mlsSession) {
          this._initMLSSessionIfNeeded(payload.d.protocol_version)
          this._ensureKeyPackageSent()
        }

        if (this.mlsSession) {
          try {
            const needsReady = this.mlsSession.prepareTransition(payload.d)
            if (needsReady) {
              this._wsSendJSON(DAVE_OPCODES.TRANSITION_READY, {
                transition_id: payload.d.transition_id
              })
            }
          } catch (e) {
            this.emit(
              'error',
              new Error(`[DAVE] Failed to prepare transition: ${e.message}`)
            )
          }
        }

        break
      }

      case DAVE_OPCODES.EXECUTE_TRANSITION: {
        if (this.mlsSession) {
          try {
            this.mlsSession.executeTransition(payload.d.transition_id)
          } catch (e) {
            this.emit(
              'error',
              new Error(`[DAVE] Failed to execute transition: ${e.message}`)
            )
          }
        }
        break
      }

      case DAVE_OPCODES.PREPARE_EPOCH: {
        if (payload.d?.protocol_version > 0 && !this.mlsSession) {
          this._initMLSSessionIfNeeded(payload.d.protocol_version)
        }

        if (this.mlsSession) {
          try {
            this.mlsSession.prepareEpoch(payload.d)

            if (payload.d?.epoch === 1) {
              this._ensureKeyPackageSent()
            }

            const transitionId = payload.d?.transition_id
            if (typeof transitionId === 'number') {
              this._wsSendJSON(DAVE_OPCODES.TRANSITION_READY, {
                transition_id: transitionId
              })
            }
          } catch (e) {
            this.emit(
              'error',
              new Error(`[DAVE] Failed to prepare epoch: ${e.message}`)
            )
          }
        }

        break
      }
    }
  }

  _sendEncryptedPacket(packet) {
    if (this._sendPacketViaQueue(packet)) return
    this.player.lastPacketTime = performance.now()
    this.udpSend(packet, this._onUdpSend)
  }

  sendAudioChunk(chunk) {
    const udpInfo = this.udpInfo
    if (!udpInfo?.secretKey) {
      if (!this._loggedMissingSecretKey) {
        this._loggedMissingSecretKey = true
        this.emit(
          'error',
          new Error(
            `sendAudioChunk: UDP secretKey missing (udpInfo=${!!udpInfo})`
          )
        )
      }
      return
    }
    this._loggedMissingSecretKey = false

    if (this.mlsSession && this.connectedUserIds.size > 0) {
      chunk = this.mlsSession.encrypt(chunk)
      if (!chunk) return
    }

    this._sendBuffer[0] = 0x80
    this._sendBuffer[1] = 0x78
    this._sendBuffer.writeUInt16BE(this.player.sequence, 2)
    this._sendBuffer.writeUInt32BE(this.player.timestamp, 4)
    this._sendBuffer.writeUInt32BE(udpInfo.ssrc, 8)

    this.player.timestamp = (this.player.timestamp + TIMESTAMP_INCREMENT) >>> 0
    this.player.sequence = (this.player.sequence + 1) & 0xffff
    this.nonce = (this.nonce + 1) >>> 0
    this.nonceBuffer.writeUInt32BE(this.nonce, 0)

    const header = this._sendBuffer.subarray(0, 12)

    switch (this.encryption) {
      case 'aead_aes256_gcm_rtpsize': {
        const cipher = crypto.createCipheriv(
          'aes-256-gcm',
          udpInfo.secretKey,
          this.nonceBuffer
        )
        cipher.setAAD(header)

        const ciphertext = cipher.update(chunk)
        ciphertext.copy(this._sendBuffer, 12)
        let off = 12 + ciphertext.length

        const final = cipher.final()
        if (final.length) {
          final.copy(this._sendBuffer, off)
          off += final.length
        }

        const authTag = cipher.getAuthTag()
        authTag.copy(this._sendBuffer, off)
        off += authTag.length

        const packetSize = off + 4
        const packet = this._sendBuffer.subarray(0, packetSize)

        packet.writeUInt32BE(this.nonce, off)

        return this._sendEncryptedPacket(packet)
      }

      case 'aead_xchacha20_poly1305_rtpsize': {
        const abytes = Sodium.ABYTES ?? 16
        const cipherLen = chunk.length + abytes
        const packetSize = 12 + cipherLen + 4
        const packet = this._sendBuffer.subarray(0, packetSize)

        const out = packet.subarray(12, 12 + cipherLen)

        if (Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_into) {
          Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_into(
            out,
            chunk,
            header,
            this.nonceBuffer,
            udpInfo.secretKey
          )
        } else {
          const encrypted = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            chunk,
            header,
            this.nonceBuffer,
            udpInfo.secretKey
          )
          encrypted.copy(out)
        }

        packet.writeUInt32BE(this.nonce, 12 + cipherLen)

        return this._sendEncryptedPacket(packet)
      }

      default:
        return
    }
  }

  play(audioStream) {
    if (!this.udpInfo) {
      this.emit('error', new Error('Cannot play audio without UDP info.'))
      return
    }

    const oldAudioStream = this.audioStream

    audioStream.once('readable', () => {
      if (oldAudioStream) {
        oldAudioStream.removeListener(
          'finishBuffering',
          this._boundMarkAsStoppable
        )
      }

      if (oldAudioStream && this.playTimeout) {
        clearTimeout(this.playTimeout)
        this.playTimeout = null

        if (this.challengeTimeout) {
          clearTimeout(this.challengeTimeout)
          this.challengeTimeout = null
        }

        this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }
      }

      this.audioStream = audioStream
      this.unpause('requested')
    })

    return oldAudioStream
  }

  stop(reason) {
    this._stopSilenceKeepalive()
    this._clearNativeQueue()

    if (this.playTimeout) {
      clearTimeout(this.playTimeout)
      this.playTimeout = null
    }

    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }

    if (this.audioStream) {
      this.audioStream.removeListener(
        'finishBuffering',
        this._boundMarkAsStoppable
      )
      this.audioStream.destroy()
      this.audioStream.removeAllListeners()
      this.audioStream = null
    }

    this._updatePlayerState({ status: 'idle', reason: reason ?? 'stopped' })

    this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }

    let silenceCount = 0
    const sendNextSilence = () => {
      if (silenceCount >= 5 || !this.udpInfo?.secretKey) return
      this.sendAudioChunk(OPUS_SILENCE_FRAME)
      silenceCount++
      if (silenceCount < 5) {
        setTimeout(sendNextSilence, 20)
      } else {
        this._wsSendJSON(5, {
          speaking: 0,
          delay: 0,
          ssrc: this.udpInfo?.ssrc ?? 0
        })
      }
    }
    sendNextSilence()
  }

  pause(reason) {
    this._clearNativeQueue()

    this._updatePlayerState({ status: 'idle', reason: reason ?? 'paused' })
    this._setSpeaking(0)

    if (this.playTimeout) {
      clearTimeout(this.playTimeout)
      this.playTimeout = null
    }

    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }
  }

  _markAsStoppable() {
    if (this.audioStream) this.audioStream.canStop = true
  }

  _packetInterval() {
    this.playTimeout = null
    if (!this.audioStream) return

    const now = performance.now()

    const lateness = now - this.player.nextPacket
    if (lateness > 100) {
      this.player.nextPacket = now
    }

    const chunk = this.audioStream.read?.(OPUS_FRAME_SIZE)

    if (chunk) {
      this._clearChallengeTimeout()
      this.sendAudioChunk(chunk)
    } else if (this.audioStream.canStop) {
      this._clearChallengeTimeout()
      return this.stop('finished')
    } else {
      this.sendAudioChunk(OPUS_SILENCE_FRAME)
      if (!this.challengeTimeout) {
        this.challengeTimeout = setTimeout(() => {
          this.challengeTimeout = null
          this.emit('stuck')
          this.pause('stuck')
        }, this.stuckTimeout ?? 2000)
      }
    }

    this.player.nextPacket += OPUS_FRAME_DURATION
    this.playTimeout = setTimeout(
      this._boundPacketInterval,
      Math.max(0, this.player.nextPacket - performance.now())
    )
  }

  _clearChallengeTimeout() {
    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }
  }

  unpause(reason) {
    this._updatePlayerState({ status: 'playing', reason: reason ?? 'unpaused' })
    this._setSpeaking(1 << 0)

    const now = performance.now()
    if (this.player.lastPacketTime) {
      const gap = now - this.player.lastPacketTime
      if (gap > OPUS_FRAME_DURATION * 2) {
        const lostframes = Math.floor(gap / OPUS_FRAME_DURATION)
        const lostTimestamp = lostframes * TIMESTAMP_INCREMENT
        this.player.timestamp = (this.player.timestamp + lostTimestamp) >>> 0
      }
    }

    this.player.nextPacket = now
    this._packetInterval()

    if (!this.audioStream.canStop) {
      this.audioStream.removeListener(
        'finishBuffering',
        this._boundMarkAsStoppable
      )
      this.audioStream.once('finishBuffering', this._boundMarkAsStoppable)
    }
  }

  _destroyConnection(code, reason) {
    if (this.hbInterval) {
      clearInterval(this.hbInterval)
      this.hbInterval = null
    }

    if (this._silenceKeepaliveTimer) {
      clearInterval(this._silenceKeepaliveTimer)
      this._silenceKeepaliveTimer = null
    }

    if (this.playTimeout) {
      clearTimeout(this.playTimeout)
      this.playTimeout = null
    }

    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }

    if (this.connectTimeout) {
      clearTimeout(this.connectTimeout)
      this.connectTimeout = null
    }

    if (this.udpKeepAliveInterval) {
      clearInterval(this.udpKeepAliveInterval)
      this.udpKeepAliveInterval = null
    }

    if (this.audioStream) {
      this.audioStream.removeListener(
        'finishBuffering',
        this._boundMarkAsStoppable
      )
    }

    if (this._nativeQueueKey !== null && this._nativeQueueManager) {
      this._destroyNativeQueue()
    }

    if (this.connectedUserIds) {
      this.connectedUserIds.clear()
    }

    this.player = {
      sequence: 0,
      timestamp: 0,
      nextPacket: 0,
      lastPacketTime: null
    }

    const ws = this.ws
    if (ws) {
      try {
        if (ws.closing) {
          ws.terminate()
        } else {
          ws.close(code, reason)
        }
      } catch {}
      ws.removeAllListeners()
      this.ws = null
    }

    if (this.udp) {
      this.udp.close()
      this.udp.removeAllListeners()
      this.udp = null
    }
  }

  _destroy(state, destroyStream) {
    this._destroyConnection(1000, 'Normal closure')

    this.udpInfo = null
    this.voiceServer = null
    this.sessionId = null

    if (this.audioStream && destroyStream) {
      this.audioStream.destroy()
      this.audioStream.removeAllListeners()
      this.audioStream = null
    }

    if (this.mlsSession) {
      this.mlsSession.destroy()
      this.mlsSession.removeAllListeners()
      this.mlsSession = null
    }

    this.pendingExternalSender = null
    this.pendingProposals = []
    this.connectedUserIds.clear()
    this._keyPackageSent = false

    for (const ssrc of this.ssrcs.keys()) {
      this._unregisterSSRC(ssrc)
    }
    this.ssrcs.clear()
    this._userIdToSSRCs.clear()

    if (this._privateQueueManager && this._nativeQueueManager) {
      if (typeof this._nativeQueueManager.close === 'function') {
        try {
          this._nativeQueueManager.close()
        } catch {}
      }
      this._nativeQueueManager = null
      this._privateQueueManager = false
    }

    this._updateState(state)
    this._updatePlayerState({ status: 'idle', reason: 'destroyed' })
  }

  destroy() {
    this._destroy({ status: 'destroyed' }, true)
  }

  voiceStateUpdate(obj) {
    this.sessionId = obj.session_id ?? obj.sessionId
  }

  voiceServerUpdate(obj) {
    const endpoint = obj.endpoint
    const token = obj.token
    const channelId = obj.channel_id ?? obj.channelId

    if (!endpoint) {
      if (this.ws) {
        this._destroyConnection(1000, 'Server update: null endpoint')
      }
      this._updateState({
        status: 'disconnected',
        reason: 'null_endpoint',
        code: 4014,
        closeReason: 'Voice server endpoint is null'
      })
      return
    }

    if (channelId) {
      this.channelId = channelId
    }

    if (
      this.voiceServer?.token === token &&
      this.voiceServer?.endpoint === endpoint
    ) {
      return
    }

    this.voiceServer = { token, endpoint }

    if (
      this.ws &&
      (this.state.status === 'connected' || this.state.status === 'connecting')
    ) {
      this.connect()
    }
  }

  getSpeakStream(ssrc) {
    return this.ssrcs.get(ssrc)?.stream
  }
}

function joinVoiceChannel(obj) {
  return new Connection(obj)
}

function getSpeakStream(ssrc, guildId) {
  if (!guildId) return null
  const guildMap = ssrcRegistry.get(guildId)
  if (!guildMap) return null
  return guildMap.get(ssrc)?.ssrcs?.get(ssrc)?.stream ?? null
}

export default {
  joinVoiceChannel,
  getSpeakStream
}
