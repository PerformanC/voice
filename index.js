import EventEmitter from 'node:events'
import dgram from 'node:dgram'
import crypto from 'node:crypto'
import { PassThrough } from 'node:stream'

import WebSocket from '@performanc/pwsl'
import Sodium from './sodium.js'

let MLS = null
try {
  MLS = await import('@snazzah/davey')
} catch {}

const MLS_PROTOCOL_VERSION = MLS?.DAVE_PROTOCOL_VERSION ?? 0

const OPUS_SAMPLE_RATE = 48000
const OPUS_FRAME_DURATION = 20
const OPUS_FRAME_SIZE = (OPUS_SAMPLE_RATE * OPUS_FRAME_DURATION) / 1000
const OPUS_SILENCE_FRAME = Buffer.from([0xf8, 0xff, 0xfe])
const TIMESTAMP_INCREMENT = (OPUS_SAMPLE_RATE / 100) * 2

const RTP_VERSION = 2
const RTP_HEADER_SIZE = 12
const RTP_PAYLOAD_TYPE = 0x78
const RTP_VERSION_SHIFT = 6
const RTP_PADDING_MASK = 0x20
const RTP_EXTENSION_MASK = 0x10
const RTP_CC_MASK = 0x0f
const HEADER_EXTENSION_MAGIC = 0xbede

const MAX_NONCE = 0x100000000
const MAX_TIMESTAMP = 0x100000000
const MAX_SEQUENCE = 0x10000

const NONCE_LENGTH_AES_GCM = 12
const NONCE_LENGTH_XCHACHA = 24
const UNPADDED_NONCE_LENGTH = 4
const AUTH_TAG_LENGTH = 16

const TRANSITION_EXPIRY = 10
const TRANSITION_EXPIRY_PENDING_DOWNGRADE = 24
const DEFAULT_DECRYPTION_FAILURE_TOLERANCE = 36

const VoiceOpcode = {
  IDENTIFY: 0,
  SELECT_PROTOCOL: 1,
  READY: 2,
  HEARTBEAT: 3,
  SESSION_DESCRIPTION: 4,
  SPEAKING: 5,
  HEARTBEAT_ACK: 6,
  RESUME: 7,
  HELLO: 8,
  RESUMED: 9,
  CLIENTS_CONNECT: 11,
  CLIENT_DISCONNECT: 13,
  DAVE_PREPARE_TRANSITION: 21,
  DAVE_EXECUTE_TRANSITION: 22,
  DAVE_TRANSITION_READY: 23,
  DAVE_PREPARE_EPOCH: 24,
  DAVE_MLS_EXTERNAL_SENDER: 25,
  DAVE_MLS_KEY_PACKAGE: 26,
  DAVE_MLS_PROPOSALS: 27,
  DAVE_MLS_COMMIT_WELCOME: 28,
  DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION: 29,
  DAVE_MLS_WELCOME: 30,
  DAVE_MLS_INVALID_COMMIT_WELCOME: 31
}

const VoiceCloseCode = {
  UNKNOWN_OPCODE: 4001,
  FAILED_TO_DECODE_PAYLOAD: 4002,
  NOT_AUTHENTICATED: 4003,
  AUTHENTICATION_FAILED: 4004,
  ALREADY_AUTHENTICATED: 4005,
  SESSION_NO_LONGER_VALID: 4006,
  SESSION_TIMEOUT: 4009,
  SERVER_NOT_FOUND: 4011,
  UNKNOWN_PROTOCOL: 4012,
  DISCONNECTED: 4014,
  VOICE_SERVER_CRASHED: 4015,
  UNKNOWN_ENCRYPTION_MODE: 4016
}

const RECONNECTABLE_CLOSE_CODES = new Set([
  1006,
  VoiceCloseCode.SESSION_TIMEOUT,
  VoiceCloseCode.VOICE_SERVER_CRASHED
])

const EncryptionMode = {
  AEAD_AES256_GCM_RTPSIZE: 'aead_aes256_gcm_rtpsize',
  AEAD_XCHACHA20_POLY1305_RTPSIZE: 'aead_xchacha20_poly1305_rtpsize'
}

const SpeakingFlags = {
  MICROPHONE: 1
}

const ssrcs = {}

class VoiceMLS extends EventEmitter {
  constructor(protocolVersion, userId, channelId, mlsLib, options = {}) {
    super()
    if (!mlsLib)
      throw new Error(
        'MLS library (@snazzah/davey) is required but not available'
      )

    this._mls = mlsLib
    this._protocolVersion = protocolVersion
    this._userId = userId
    this._channelId = channelId
    this._options = options
    this._session = null
    this._lastTransitionId = undefined
    this._pendingTransition = undefined
    this._downgraded = false
    this._consecutiveFailures = 0
    this._reinitializing = false
    this._failureTolerance =
      options.decryptionFailureTolerance ?? DEFAULT_DECRYPTION_FAILURE_TOLERANCE

    this._initialize()
  }

  get protocolVersion() {
    return this._protocolVersion
  }
  get session() {
    return this._session
  }
  get ready() {
    return this._session?.ready ?? false
  }
  get isDowngraded() {
    return this._downgraded
  }
  get isReinitializing() {
    return this._reinitializing
  }
  get hasPendingTransition() {
    return this._pendingTransition !== undefined
  }

  get voicePrivacyCode() {
    if (this._protocolVersion === 0 || !this._session?.voicePrivacyCode)
      return null
    return this._session.voicePrivacyCode
  }

  _initialize() {
    if (this._protocolVersion > 0) {
      this._initializeSession()
      this._emitKeyPackage()
    } else if (this._session) {
      this._session.reset()
      this._session.setPassthroughMode(true, TRANSITION_EXPIRY)
    }
  }

  _initializeSession() {
    if (this._session) {
      this._session.reinit(this._protocolVersion, this._userId, this._channelId)
    } else {
      this._session = new this._mls.DAVESession(
        this._protocolVersion,
        this._userId,
        this._channelId
      )
    }
  }

  _emitKeyPackage() {
    if (!this._session) return
    try {
      this.emit('keyPackage', this._session.getSerializedKeyPackage())
    } catch (error) {
      this.emit(
        'error',
        new Error(`Failed to get key package: ${error.message}`)
      )
    }
  }

  async getVerificationCode(userId) {
    if (!this._session) throw new Error('Session not available')
    return this._session.getVerificationCode(userId)
  }

  reinit() {
    this._initialize()
  }

  setExternalSender(externalSender) {
    if (!this._session) throw new Error('No session available')
    this._session.setExternalSender(externalSender)
  }

  getSerializedKeyPackage() {
    if (!this._session) throw new Error('No session available')
    return this._session.getSerializedKeyPackage()
  }

  prepareTransition(data) {
    const { transition_id: transitionId, protocol_version: protocolVersion } =
      data
    this._pendingTransition = { transitionId, protocolVersion }

    if (transitionId === 0) {
      this._executeTransitionInternal(transitionId)
      return false
    }

    if (protocolVersion === 0) {
      this._session?.setPassthroughMode(
        true,
        TRANSITION_EXPIRY_PENDING_DOWNGRADE
      )
    }
    return true
  }

  executeTransition(transitionId) {
    return this._executeTransitionInternal(transitionId)
  }

  _executeTransitionInternal(transitionId) {
    if (
      !this._pendingTransition ||
      transitionId !== this._pendingTransition.transitionId
    ) {
      this._pendingTransition = undefined
      return false
    }

    const oldVersion = this._protocolVersion
    this._protocolVersion = this._pendingTransition.protocolVersion

    if (oldVersion !== this._protocolVersion && this._protocolVersion === 0) {
      this._downgraded = true
    } else if (transitionId > 0 && this._downgraded) {
      this._downgraded = false
      this._session?.setPassthroughMode(true, TRANSITION_EXPIRY)
    }

    this._reinitializing = false
    this._lastTransitionId = transitionId
    this._pendingTransition = undefined
    return true
  }

  prepareEpoch(data) {
    if (data.epoch === 1) {
      this._protocolVersion = data.protocol_version
      this.reinit()
    }
  }

  recoverFromInvalidTransition(transitionId) {
    if (this._reinitializing) return
    this._reinitializing = true
    this._consecutiveFailures = 0
    this.emit('invalidateTransition', transitionId)
    this.reinit()
  }

  processProposals(payload, connectedClients) {
    if (!this._session) throw new Error('No session available')

    const { commit, welcome } = this._session.processProposals(
      payload.readUInt8(0),
      payload.subarray(1),
      Array.from(connectedClients)
    )

    if (!commit) return null
    return welcome ? Buffer.concat([commit, welcome]) : commit
  }

  processCommit(payload) {
    if (!this._session) throw new Error('No session available')

    const transitionId = payload.readUInt16BE(0)
    try {
      this._session.processCommit(payload.subarray(2))
      if (transitionId === 0) {
        this._reinitializing = false
        this._lastTransitionId = transitionId
      } else {
        this._pendingTransition = {
          transitionId,
          protocolVersion: this._protocolVersion
        }
      }
      return { transitionId, success: true }
    } catch (error) {
      this.recoverFromInvalidTransition(transitionId)
      return { transitionId, success: false, error }
    }
  }

  processWelcome(payload) {
    if (!this._session) throw new Error('No session available')

    const transitionId = payload.readUInt16BE(0)
    try {
      this._session.processWelcome(payload.subarray(2))
      if (transitionId === 0) {
        this._reinitializing = false
        this._lastTransitionId = transitionId
      } else {
        this._pendingTransition = {
          transitionId,
          protocolVersion: this._protocolVersion
        }
      }
      return { transitionId, success: true }
    } catch (error) {
      this.recoverFromInvalidTransition(transitionId)
      return { transitionId, success: false, error }
    }
  }

  encrypt(packet, silenceFrame) {
    if (
      this._protocolVersion === 0 ||
      !this._session?.ready ||
      packet.equals(silenceFrame)
    ) {
      return packet
    }
    try {
      return this._session.encryptOpus(packet)
    } catch (error) {
      this.emit('error', new Error(`Encryption failed: ${error.message}`))
      return packet
    }
  }

  decrypt(packet, userId, silenceFrame) {
    if (packet.equals(silenceFrame)) return packet

    const canDecrypt =
      this._session?.ready &&
      (this._protocolVersion !== 0 || this._session?.canPassthrough(userId))
    if (!canDecrypt || !this._session) return packet

    try {
      const decrypted = this._session.decrypt(
        userId,
        this._mls.MediaType.AUDIO,
        packet
      )
      this._consecutiveFailures = 0
      return decrypted
    } catch (error) {
      return this._handleDecryptionError(error)
    }
  }

  _handleDecryptionError(error) {
    if (this._reinitializing || this._pendingTransition) return null

    this._consecutiveFailures++
    if (this._consecutiveFailures > this._failureTolerance) {
      if (this._lastTransitionId !== undefined) {
        this.recoverFromInvalidTransition(this._lastTransitionId)
      } else {
        throw error
      }
    }
    return null
  }

  destroy() {
    try {
      if (this._session) {
        this._session.reset()
        this._session = null
      }
    } catch {}
    this.removeAllListeners()
  }
}

class RTPPacketParser {
  constructor(data) {
    this._data = data
    this._valid = false
    this._headerSize = RTP_HEADER_SIZE
    this._extensionLength = 0
    this._parse()
  }

  get valid() {
    return this._valid
  }
  get version() {
    return this._data[0] >> RTP_VERSION_SHIFT
  }
  get hasPadding() {
    return (this._data[0] & RTP_PADDING_MASK) !== 0
  }
  get hasExtension() {
    return (this._data[0] & RTP_EXTENSION_MASK) !== 0
  }
  get csrcCount() {
    return this._data[0] & RTP_CC_MASK
  }
  get payloadType() {
    return this._data[1]
  }
  get sequence() {
    return this._data.readUInt16BE(2)
  }
  get timestamp() {
    return this._data.readUInt32BE(4)
  }
  get ssrc() {
    return this._data.readUInt32BE(8)
  }
  get headerSize() {
    return this._headerSize
  }
  get extensionLengthBytes() {
    return this._extensionLength
  }
  get header() {
    return this._data.subarray(0, this._headerSize)
  }

  _parse() {
    if (
      this._data.length < RTP_HEADER_SIZE ||
      this.version !== RTP_VERSION ||
      this.payloadType !== RTP_PAYLOAD_TYPE
    ) {
      return
    }

    this._headerSize = RTP_HEADER_SIZE + this.csrcCount * 4
    if (this._data.length < this._headerSize) return

    if (this.hasExtension) {
      if (this._data.length < this._headerSize + 4) return
      if (this._data.readUInt16BE(this._headerSize) !== HEADER_EXTENSION_MAGIC)
        return

      this._extensionLength = this._data.readUInt16BE(this._headerSize + 2) * 4
      this._headerSize += 4
    }
    this._valid = true
  }
}

class VoiceEncryption {
  constructor(mode, secretKey) {
    this._mode = mode
    this._secretKey = secretKey
    this._nonce = 0
    this._isAesGcm = mode === EncryptionMode.AEAD_AES256_GCM_RTPSIZE
    this._nonceBuffer = Buffer.alloc(
      this._isAesGcm ? NONCE_LENGTH_AES_GCM : NONCE_LENGTH_XCHACHA
    )
  }

  get mode() {
    return this._mode
  }

  _incrementNonce() {
    this._nonce = (this._nonce + 1) % MAX_NONCE
    this._nonceBuffer.writeUInt32LE(this._nonce, 0)
  }

  getNoncePadding() {
    return this._nonceBuffer.subarray(0, UNPADDED_NONCE_LENGTH)
  }

  encrypt(header, payload) {
    this._incrementNonce()

    const encrypted = this._isAesGcm
      ? this._encryptAesGcm(header, payload)
      : this._encryptXChaCha(header, payload)

    return Buffer.concat([header, encrypted, this.getNoncePadding()])
  }

  _encryptAesGcm(header, payload) {
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      this._secretKey,
      this._nonceBuffer
    )
    cipher.setAAD(header)
    return Buffer.concat([
      cipher.update(payload),
      cipher.final(),
      cipher.getAuthTag()
    ])
  }

  _encryptXChaCha(header, payload) {
    return Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      payload,
      header,
      this._nonceBuffer,
      this._secretKey
    )
  }

  decrypt(packet, rtpParser) {
    const nonceBuffer = Buffer.alloc(
      this._isAesGcm ? NONCE_LENGTH_AES_GCM : NONCE_LENGTH_XCHACHA
    )
    packet.copy(
      nonceBuffer,
      0,
      packet.length - UNPADDED_NONCE_LENGTH,
      packet.length
    )

    const decrypted = this._isAesGcm
      ? this._decryptAesGcm(packet, rtpParser, nonceBuffer)
      : this._decryptXChaCha(packet, rtpParser, nonceBuffer)

    if (decrypted === null) return null
    return this._removeExtension(
      this._removePadding(decrypted, rtpParser.hasPadding),
      rtpParser
    )
  }

  _decryptAesGcm(packet, rtpParser, nonceBuffer) {
    const headerSize = rtpParser.headerSize
    const trailerLength = AUTH_TAG_LENGTH + UNPADDED_NONCE_LENGTH

    if (packet.length < headerSize + trailerLength) return null

    const encrypted = packet.subarray(headerSize, packet.length - trailerLength)
    const authTag = packet.subarray(
      packet.length - trailerLength,
      packet.length - UNPADDED_NONCE_LENGTH
    )

    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this._secretKey,
        nonceBuffer
      )
      decipher.setAAD(rtpParser.header)
      decipher.setAuthTag(authTag)
      return Buffer.concat([decipher.update(encrypted), decipher.final()])
    } catch {
      return null
    }
  }

  _decryptXChaCha(packet, rtpParser, nonceBuffer) {
    const headerSize = rtpParser.headerSize
    if (packet.length < headerSize + UNPADDED_NONCE_LENGTH) return null

    try {
      return Buffer.from(
        Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          packet.subarray(headerSize, packet.length - UNPADDED_NONCE_LENGTH),
          rtpParser.header,
          nonceBuffer,
          this._secretKey
        )
      )
    } catch {
      return null
    }
  }

  _removePadding(data, hasPadding) {
    if (!hasPadding) return data
    const paddingAmount = data.readUInt8(data.length - 1)
    return paddingAmount >= data.length
      ? data
      : data.subarray(0, data.length - paddingAmount)
  }

  _removeExtension(data, rtpParser) {
    const extLen = rtpParser.extensionLengthBytes
    if (!rtpParser.hasExtension || extLen <= 0 || extLen >= data.length)
      return data
    return data.subarray(extLen)
  }
}

class Connection extends EventEmitter {
  constructor(obj) {
    super()

    this.guildId = obj.guildId
    this.userId = obj.userId
    this.channelId = null
    this.encryption = obj.encryption

    this.ws = null
    this.state = { status: 'disconnected' }
    this.playerState = { status: 'idle' }

    this.sessionId = null
    this.voiceServer = null
    this.hbInterval = null
    this.udpInfo = null
    this.udp = null

    this.ping = -1
    this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }
    this.player = { sequence: 0, timestamp: 0, nextPacket: 0 }

    this.nonce = 0
    this.nonceBuffer = Buffer.alloc(
      this.encryption === EncryptionMode.AEAD_AES256_GCM_RTPSIZE
        ? NONCE_LENGTH_AES_GCM
        : NONCE_LENGTH_XCHACHA
    )
    this.packetBuffer = Buffer.allocUnsafe(RTP_HEADER_SIZE)

    this.playTimeout = null
    this.challengeTimeout = null
    this.audioStream = null
    this.lastSequence = -1

    this.mlsSession = null
    this.mlsProtocolVersion = 0

    this._sendEncryption = null
    this._receiveEncryption = null
    this._boundMarkAsStoppable = this._markAsStoppable.bind(this)
  }

  _wsSend(op, d) {
    if (this.ws) this.ws.send(JSON.stringify({ op, d }))
  }

  udpSend(data, cb) {
    if (!this.udp) return
    this.udp.send(
      data,
      this.udpInfo.port,
      this.udpInfo.ip,
      cb ||
        ((error) => {
          if (error) this.emit('error', error)
        })
    )
  }

  _setSpeaking(value) {
    if (!this.ws || !this.udpInfo) return
    this._wsSend(VoiceOpcode.SPEAKING, {
      speaking: value,
      delay: 0,
      ssrc: this.udpInfo.ssrc
    })
  }

  _updateState(state) {
    this.emit('stateChange', this.state, state)
    this.state = state
  }

  _updatePlayerState(state) {
    this.emit('playerStateChange', this.playerState, state)
    this.playerState = state
  }

  _initMLSSession() {
    if (!MLS || this.mlsProtocolVersion === 0) return

    if (!this.channelId) {
      this.emit(
        'error',
        new Error('[MLS] Cannot initialize - channelId not set.')
      )
      return
    }

    try {
      this.mlsSession = new VoiceMLS(
        this.mlsProtocolVersion,
        this.userId,
        this.channelId,
        MLS
      )

      this.mlsSession.on('error', (err) => this.emit('error', err))

      this.mlsSession.on('keyPackage', (keyPackage) => {
        this._wsSend(VoiceOpcode.DAVE_MLS_KEY_PACKAGE, {
          key_package: keyPackage.toString('base64')
        })
      })

      this.mlsSession.on('invalidateTransition', (transitionId) => {
        this._wsSend(VoiceOpcode.DAVE_MLS_INVALID_COMMIT_WELCOME, {
          transition_id: transitionId
        })
      })
    } catch (error) {
      this.emit(
        'error',
        new Error(`[MLS] Failed to initialize session: ${error.message}`)
      )
    }
  }

  _ipDiscovery() {
    return new Promise((resolve) => {
      this.udp.once('message', (message) => {
        if (message.readUInt16BE(0) !== 2) return
        resolve({
          ip: message.subarray(8, message.indexOf(0, 8)).toString('utf8'),
          port: message.readUInt16BE(message.length - 2)
        })
      })

      const discoveryBuffer = Buffer.alloc(74)
      discoveryBuffer.writeUInt16BE(1, 0)
      discoveryBuffer.writeUInt16BE(70, 2)
      discoveryBuffer.writeUInt32BE(this.udpInfo.ssrc, 4)
      this.udpSend(discoveryBuffer)
    })
  }

  _cleanupSsrc(userId) {
    for (const ssrc of Object.keys(ssrcs)) {
      if (ssrcs[ssrc]?.userId === userId) {
        if (ssrcs[ssrc].stream && !ssrcs[ssrc].stream.destroyed) {
          ssrcs[ssrc].stream.destroy()
        }
        delete ssrcs[ssrc]
      }
    }
  }

  connect(cb, reconnection) {
    if (this.ws) {
      this._destroyConnection(1000, 'Normal close')
      this._updateState({
        status: 'disconnected',
        reason: 'closed',
        code: VoiceCloseCode.DISCONNECTED,
        closeReason: 'Disconnected.'
      })
      this._updatePlayerState({ status: 'idle', reason: 'destroyed' })
    }

    this._updateState({ status: 'connecting' })

    this.ws = new WebSocket(`wss://${this.voiceServer.endpoint}/?v=8`, {
      headers: {
        'User-Agent': 'DiscordBot (https://github.com/PerformanC/voice, 2.2.0)'
      }
    })

    this.ws.on('open', () => {
      if (reconnection) {
        this._wsSend(VoiceOpcode.RESUME, {
          server_id: this.guildId,
          session_id: this.sessionId,
          token: this.voiceServer.token,
          seq_ack: this.lastSequence
        })
      } else {
        this._wsSend(VoiceOpcode.IDENTIFY, {
          server_id: this.guildId,
          user_id: this.userId,
          session_id: this.sessionId,
          token: this.voiceServer.token
        })
      }
    })

    this.ws.on('message', async (data) => {
      const payload = JSON.parse(data)
      if (payload.seq) this.lastSequence = payload.seq

      switch (payload.op) {
        case VoiceOpcode.READY: {
          this.udpInfo = {
            ssrc: payload.d.ssrc,
            ip: payload.d.ip,
            port: payload.d.port,
            secretKey: null
          }
          this.udp = dgram.createSocket('udp4')
          this.udp.on('message', (msg) => this._handleUdpMessage(msg))
          this.udp.on('error', (error) => this.emit('error', error))
          this.udp.on('close', () => {
            if (this.ws) this._destroy({ status: 'disconnected' })
          })

          const serverInfo = await this._ipDiscovery()
          this._wsSend(VoiceOpcode.SELECT_PROTOCOL, {
            protocol: 'udp',
            data: {
              address: serverInfo.ip,
              port: serverInfo.port,
              mode: this.encryption
            }
          })
          break
        }

        case VoiceOpcode.SESSION_DESCRIPTION: {
          this.udpInfo.secretKey = new Uint8Array(payload.d.secret_key)
          this._sendEncryption = new VoiceEncryption(
            this.encryption,
            this.udpInfo.secretKey
          )
          this._receiveEncryption = new VoiceEncryption(
            this.encryption,
            this.udpInfo.secretKey
          )

          if (cb) cb()
          this._updateState({ status: 'connected' })
          this._updatePlayerState({ status: 'idle', reason: 'connected' })

          if (MLS && payload.d.dave_protocol_version > 0) {
            this.mlsProtocolVersion = Math.min(
              payload.d.dave_protocol_version,
              MLS_PROTOCOL_VERSION
            )
            this._initMLSSession()
          }
          break
        }

        case VoiceOpcode.SPEAKING: {
          ssrcs[payload.d.ssrc] = {
            userId: payload.d.user_id,
            stream: new PassThrough()
          }
          this.emit('speakStart', payload.d.user_id, payload.d.ssrc)
          break
        }

        case VoiceOpcode.HEARTBEAT_ACK: {
          this.ping = Date.now() - payload.d.t
          break
        }

        case VoiceOpcode.HELLO: {
          this.hbInterval = setInterval(() => {
            this._wsSend(VoiceOpcode.HEARTBEAT, {
              t: Date.now(),
              seq_ack: this.lastSequence
            })
          }, payload.d.heartbeat_interval)
          break
        }

        case VoiceOpcode.CLIENTS_CONNECT: {
          break
        }

        case VoiceOpcode.CLIENT_DISCONNECT: {
          if (payload.d?.user_id) this._cleanupSsrc(payload.d.user_id)
          break
        }

        case VoiceOpcode.DAVE_PREPARE_TRANSITION: {
          if (!this.mlsSession || !payload.d) break

          try {
            const shouldSignal = this.mlsSession.prepareTransition(payload.d)
            if (shouldSignal) {
              this._wsSend(VoiceOpcode.DAVE_TRANSITION_READY, {
                transition_id: payload.d.transition_id
              })
            }
          } catch (error) {
            this.emit(
              'error',
              new Error(`[MLS] Failed to prepare transition: ${error.message}`)
            )
          }
          break
        }

        case VoiceOpcode.DAVE_EXECUTE_TRANSITION: {
          if (!this.mlsSession || payload.d?.transition_id === undefined) break

          try {
            this.mlsSession.executeTransition(payload.d.transition_id)
          } catch (error) {
            this.emit(
              'error',
              new Error(`[MLS] Failed to execute transition: ${error.message}`)
            )
          }
          break
        }

        case VoiceOpcode.DAVE_TRANSITION_READY: {
          break
        }

        case VoiceOpcode.DAVE_PREPARE_EPOCH: {
          if (!this.mlsSession || !payload.d) break

          try {
            this.mlsSession.prepareEpoch(payload.d)
          } catch (error) {
            this.emit(
              'error',
              new Error(`[MLS] Failed to prepare epoch: ${error.message}`)
            )
          }
          break
        }

        case VoiceOpcode.DAVE_MLS_EXTERNAL_SENDER: {
          if (!this.mlsSession || !payload.d?.external_sender_package) break

          try {
            const buffer = Buffer.from(
              payload.d.external_sender_package,
              'base64'
            )
            this.mlsSession.setExternalSender(buffer)
          } catch (error) {
            this.emit(
              'error',
              new Error(`[MLS] Failed to set external sender: ${error.message}`)
            )
          }
          break
        }

        case VoiceOpcode.DAVE_MLS_KEY_PACKAGE: {
          break
        }

        case VoiceOpcode.DAVE_MLS_PROPOSALS: {
          if (!this.mlsSession || !payload.d?.proposals) break

          try {
            const proposals = Buffer.from(payload.d.proposals, 'base64')
            const connectedClients = new Set(
              Object.keys(ssrcs)
                .map((ssrc) => ssrcs[ssrc]?.userId)
                .filter(Boolean)
            )

            const response = this.mlsSession.processProposals(
              proposals,
              connectedClients
            )
            if (response) {
              this._wsSend(VoiceOpcode.DAVE_MLS_COMMIT_WELCOME, {
                commit_message: response.toString('base64')
              })
            }
          } catch (error) {
            this.emit(
              'error',
              new Error(`[MLS] Failed to process proposals: ${error.message}`)
            )
          }
          break
        }

        case VoiceOpcode.DAVE_MLS_COMMIT_WELCOME: {
          if (!this.mlsSession || !payload.d) break

          try {
            const transitionId = payload.d.transition_id

            if (payload.d.commit_message) {
              const buffer = Buffer.from(payload.d.commit_message, 'base64')
              const fullBuffer = Buffer.allocUnsafe(buffer.length + 2)
              fullBuffer.writeUInt16BE(transitionId, 0)
              buffer.copy(fullBuffer, 2)

              const result = this.mlsSession.processCommit(fullBuffer)
              if (result.success) {
                this._wsSend(VoiceOpcode.DAVE_TRANSITION_READY, {
                  transition_id: result.transitionId
                })
              }
            }

            if (payload.d.welcome_message) {
              const buffer = Buffer.from(payload.d.welcome_message, 'base64')
              const fullBuffer = Buffer.allocUnsafe(buffer.length + 2)
              fullBuffer.writeUInt16BE(transitionId, 0)
              buffer.copy(fullBuffer, 2)

              const result = this.mlsSession.processWelcome(fullBuffer)
              if (result.success) {
                this._wsSend(VoiceOpcode.DAVE_TRANSITION_READY, {
                  transition_id: result.transitionId
                })
              }
            }
          } catch (error) {
            this.emit(
              'error',
              new Error(
                `[MLS] Failed to process commit/welcome: ${error.message}`
              )
            )
          }
          break
        }

        case VoiceOpcode.DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION: {
          if (!this.mlsSession || payload.d?.transition_id === undefined) break

          this._wsSend(VoiceOpcode.DAVE_TRANSITION_READY, {
            transition_id: payload.d.transition_id
          })
          break
        }

        case VoiceOpcode.DAVE_MLS_WELCOME: {
          if (!this.mlsSession || !payload.d) break

          try {
            const transitionId = payload.d.transition_id
            const buffer = Buffer.from(payload.d.welcome_message, 'base64')
            const fullBuffer = Buffer.allocUnsafe(buffer.length + 2)
            fullBuffer.writeUInt16BE(transitionId, 0)
            buffer.copy(fullBuffer, 2)

            const result = this.mlsSession.processWelcome(fullBuffer)
            if (result.success) {
              this._wsSend(VoiceOpcode.DAVE_TRANSITION_READY, {
                transition_id: result.transitionId
              })
            }
          } catch (error) {
            this.emit(
              'error',
              new Error(`[MLS] Failed to process welcome: ${error.message}`)
            )
          }
          break
        }

        case VoiceOpcode.DAVE_MLS_INVALID_COMMIT_WELCOME: {
          if (!this.mlsSession || payload.d?.transition_id === undefined) break

          try {
            this.mlsSession.recoverFromInvalidTransition(
              payload.d.transition_id
            )
          } catch (error) {
            this.emit(
              'error',
              new Error(
                `[MLS] Failed to recover from invalid transition: ${error.message}`
              )
            )
          }
          break
        }
      }
    })

    this.ws.on('close', (code, reason) => {
      if (!this.ws) return

      if (RECONNECTABLE_CLOSE_CODES.has(code)) {
        this._destroyConnection(code, reason)
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

  _handleUdpMessage(data) {
    if (data.length <= RTP_HEADER_SIZE) return

    const rtpParser = new RTPPacketParser(data)
    if (!rtpParser.valid || !this.udpInfo.secretKey || !this._receiveEncryption)
      return

    const userData = ssrcs[rtpParser.ssrc]
    if (!userData) return

    const decryptedPacket = this._receiveEncryption.decrypt(data, rtpParser)
    if (!decryptedPacket) return

    let packet = decryptedPacket
    if (this.mlsSession && userData.userId) {
      const decrypted = this.mlsSession.decrypt(
        packet,
        userData.userId,
        OPUS_SILENCE_FRAME
      )
      if (decrypted === null) return
      packet = decrypted
    }

    if (packet.compare(OPUS_SILENCE_FRAME) === 0) {
      if (userData.stream._readableState.ended) return
      this.emit('speakEnd', userData.userId, rtpParser.ssrc)
      userData.stream.push(null)
    } else {
      if (userData.stream._readableState.ended) {
        userData.stream = new PassThrough()
        this.emit('speakStart', userData.userId, rtpParser.ssrc)
      }
      userData.stream.write(packet)
    }
  }

  sendAudioChunk(chunk) {
    if (!this.udpInfo?.secretKey || !this._sendEncryption) return

    if (this.mlsSession)
      chunk = this.mlsSession.encrypt(chunk, OPUS_SILENCE_FRAME)

    this.packetBuffer.writeUInt8(0x80, 0)
    this.packetBuffer.writeUInt8(RTP_PAYLOAD_TYPE, 1)
    this.packetBuffer.writeUInt16BE(this.player.sequence, 2)
    this.packetBuffer.writeUInt32BE(this.player.timestamp, 4)
    this.packetBuffer.writeUInt32BE(this.udpInfo.ssrc, 8)

    this.player.timestamp =
      (this.player.timestamp + TIMESTAMP_INCREMENT) % MAX_TIMESTAMP
    this.player.sequence = (this.player.sequence + 1) % MAX_SEQUENCE

    const packet = this._sendEncryption.encrypt(this.packetBuffer, chunk)

    this.udpSend(packet, (error) => {
      if (error) this.statistics.packetsLost++
      else this.statistics.packetsSent++
      this.statistics.packetsExpected++
    })
  }

  play(audioStream) {
    if (!this.udpInfo) {
      this.emit('error', new Error('Cannot play audio without UDP info.'))
      return
    }

    const oldAudioStream = this.audioStream

    audioStream.once('readable', () => {
      if (oldAudioStream && this.playTimeout) {
        clearTimeout(this.playTimeout)
        this.playTimeout = null

        if (this.challengeTimeout) {
          clearTimeout(this.challengeTimeout)
          this.challengeTimeout = null
        }

        this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }
        oldAudioStream.removeListener(
          'finishBuffering',
          this._boundMarkAsStoppable
        )
      }

      this.audioStream = audioStream
      this.unpause('requested')
    })

    return oldAudioStream
  }

  stop(reason) {
    clearTimeout(this.playTimeout)
    this.playTimeout = null

    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }

    if (this.audioStream) {
      this.audioStream.destroy()
      this.audioStream.removeAllListeners()
      this.audioStream = null
    }

    this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }
    this._updatePlayerState({ status: 'idle', reason: reason ?? 'stopped' })
    this.udpSend(OPUS_SILENCE_FRAME)
    this._setSpeaking(0)
  }

  pause(reason) {
    this._updatePlayerState({ status: 'idle', reason: reason ?? 'paused' })
    this._setSpeaking(0)
    clearTimeout(this.playTimeout)

    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }
  }

  _markAsStoppable() {
    if (this.audioStream) this.audioStream.canStop = true
  }

  _packetInterval() {
    this.playTimeout = setTimeout(
      () => {
        if (!this.audioStream) return

        const chunk = this.audioStream.read(OPUS_FRAME_SIZE)

        if (!chunk && this.audioStream.canStop) {
          if (this.challengeTimeout) {
            clearTimeout(this.challengeTimeout)
            this.challengeTimeout = null
          }
          return this.stop('finished')
        }

        if (chunk) {
          if (this.challengeTimeout) {
            clearTimeout(this.challengeTimeout)
            this.challengeTimeout = null
          }
          this.sendAudioChunk(chunk)
        } else if (!this.challengeTimeout) {
          this.challengeTimeout = setTimeout(() => {
            this.emit('stuck')
            this.challengeTimeout = null
            this.pause('stuck')
          }, 2000)
        }

        this.player.nextPacket += OPUS_FRAME_DURATION
        this._packetInterval()
      },
      Math.max(0, this.player.nextPacket - Date.now())
    )
  }

  unpause(reason) {
    this._updatePlayerState({ status: 'playing', reason: reason ?? 'unpaused' })
    this._setSpeaking(SpeakingFlags.MICROPHONE)

    this.player.nextPacket = Date.now() + OPUS_FRAME_DURATION
    this._packetInterval()

    if (!this.audioStream.canStop) {
      this.audioStream.once('finishBuffering', this._boundMarkAsStoppable)
    }
  }

  _destroyConnection(code, reason) {
    if (this.hbInterval) {
      clearInterval(this.hbInterval)
      this.hbInterval = null
    }

    if (this.playTimeout) {
      clearTimeout(this.playTimeout)
      this.playTimeout = null
    }

    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }

    this.player = { sequence: 0, timestamp: 0, nextPacket: 0 }

    if (this.ws && !this.ws.closing) {
      this.ws.close(code, reason)
      this.ws.removeAllListeners()
      this.ws = null
    }

    if (this.udp) {
      this.udp.close()
      this.udp.removeAllListeners()
      this.udp = null
    }

    this._sendEncryption = null
    this._receiveEncryption = null
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

    this._updateState(state)
    this._updatePlayerState({ status: 'idle', reason: 'destroyed' })
  }

  destroy() {
    this._destroy({ status: 'destroyed' }, true)
  }

  voiceStateUpdate(obj) {
    this.sessionId = obj.session_id
  }

  voiceServerUpdate(obj) {
    if (
      this.voiceServer?.token === obj.token &&
      this.voiceServer?.endpoint === obj.endpoint
    )
      return
    if (obj.channel_id) this.channelId = obj.channel_id
    this.voiceServer = { token: obj.token, endpoint: obj.endpoint }
  }
}

function joinVoiceChannel(obj) {
  return new Connection(obj)
}

function getSpeakStream(ssrc) {
  return ssrcs[ssrc]?.stream
}

export default {
  joinVoiceChannel,
  getSpeakStream
}
