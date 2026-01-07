import EventEmitter from 'node:events'
import dgram from 'node:dgram'
import crypto from 'node:crypto'
import { PassThrough } from 'node:stream'
import WebSocket from '@performanc/pwsl'
import Sodium from './sodium.js'

let MLS = null
try {
  const lib = await import('@snazzah/davey')
  MLS = lib
} catch (err) {
  // MLS not available
}

const MLS_PROTOCOL_VERSION = MLS?.DAVE_PROTOCOL_VERSION ?? 0

const OPUS_SAMPLE_RATE = 48000
const OPUS_FRAME_DURATION = 20
const OPUS_SILENCE_FRAME = Buffer.from([0xf8, 0xff, 0xfe])

const TIMESTAMP_INCREMENT = (OPUS_SAMPLE_RATE / 1000) * OPUS_FRAME_DURATION
const OPUS_FRAME_SIZE = (OPUS_SAMPLE_RATE * OPUS_FRAME_DURATION) / 1000
const MAX_NONCE = 2 ** 32
const MAX_TIMESTAMP = 2 ** 32
const MAX_SEQUENCE = 2 ** 16

const DISCORD_CLOSE_CODES = {
  1006: { reconnect: true },
  4014: { error: false },
  4015: { reconnect: true }
}

const ssrcs = {}

const TRANSITION_EXPIRY = 10
const TRANSITION_EXPIRY_PENDING_DOWNGRADE = 24
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

    if (!MLS)
      throw new Error(
        'MLS library (@snazzah/davey) is required but not available'
      )

    this.MLS = MLS
    this.protocolVersion = protocolVersion
    this.userId = userId
    this.channelId = channelId

    this.lastTransitionId = undefined
    this.pendingTransition = undefined
    this.downgraded = false

    this.consecutiveFailures = 0
    this.reinitializing = false
    this.failureTolerance =
      options.decryptionFailureTolerance ?? DEFAULT_DECRYPTION_FAILURE_TOLERANCE

    this.session = null

    this.externalSender = null
    this.externalSenderSet = false

    this._pendingKeyPackage = null

    this.reinit({ emitKeyPackage: false })
  }

  reinit({ emitKeyPackage } = { emitKeyPackage: true }) {
    this.externalSenderSet = false

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
        } catch (e) {
          // Failed to re-apply external sender
        }
      }

      const keyPackage = this.session.getSerializedKeyPackage()
      this._pendingKeyPackage = keyPackage

      if (emitKeyPackage) {
        this.emit('keyPackage', keyPackage)
      }

      return
    }

    if (this.session) {
      try {
        this.session.reset()
      } catch {}
      try {
        this.session.setPassthroughMode(true, TRANSITION_EXPIRY)
      } catch (e) {
        // Failed to enable passthrough mode
      }
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

    try {
      this.session.setExternalSender(externalSender)
      this.externalSenderSet = true
    } catch (error) {
      throw error
    }
  }

  prepareTransition(data) {
    this.pendingTransition = data

    if (data.transition_id === 0) {
      this.executeTransition(data.transition_id)
      return false
    }

    if (data.protocol_version === 0) {
      try {
        this.session?.setPassthroughMode(
          true,
          TRANSITION_EXPIRY_PENDING_DOWNGRADE
        )
      } catch (e) {
        // Failed to set passthrough
      }
    }

    return true
  }

  executeTransition(transitionId) {
    if (!this.pendingTransition) return false

    let transitioned = false
    if (transitionId === this.pendingTransition.transition_id) {
      const oldVersion = this.protocolVersion
      this.protocolVersion = this.pendingTransition.protocol_version

      if (oldVersion !== this.protocolVersion && this.protocolVersion === 0) {
        this.downgraded = true
      } else if (transitionId > 0 && this.downgraded) {
        this.downgraded = false
        try {
          this.session?.setPassthroughMode(true, TRANSITION_EXPIRY)
        } catch (e) {
          // Failed to set passthrough
        }
      }

      transitioned = true
      this.reinitializing = false
      this.lastTransitionId = transitionId
    }

    this.pendingTransition = undefined
    return transitioned
  }

  prepareEpoch(data) {
    if (data.epoch === 1) {
      this.protocolVersion = data.protocol_version
      this.reinit({ emitKeyPackage: true })
    }
  }

  recoverFromInvalidTransition(transitionId) {
    if (this.reinitializing) return

    this.reinitializing = true
    this.consecutiveFailures = 0

    const currentProtocolVersion = this.protocolVersion
    this.protocolVersion = 0
    this.reinit({ emitKeyPackage: false })

    setTimeout(() => {
      if (this.protocolVersion === 0)
        this.protocolVersion = currentProtocolVersion

      this.emit('invalidateTransition', transitionId)
      this.reinit({ emitKeyPackage: true })
    }, 200)
  }

  processProposals(payload, connectedClients) {
    if (!this.session) throw new Error('No session available')

    const optype = payload.readUInt8(0)

    const { commit, welcome } = this.session.processProposals(
      optype,
      payload.subarray(1),
      Array.from(connectedClients)
    )

    if (!commit) return null

    return welcome ? Buffer.concat([commit, welcome]) : commit
  }

  processCommit(serverPayload) {
    if (!this.session) throw new Error('No session available')

    const transitionId = serverPayload.readUInt16BE(0)

    try {
      this.session.processCommit(serverPayload.subarray(2))

      if (transitionId === 0) {
        this.reinitializing = false
        this.lastTransitionId = transitionId
      } else {
        this.pendingTransition = {
          transition_id: transitionId,
          protocol_version: this.protocolVersion
        }
      }

      return { transitionId, success: true }
    } catch (error) {
      this.recoverFromInvalidTransition(transitionId)
      return { transitionId, success: false }
    }
  }

  processWelcome(serverPayload) {
    if (!this.session) throw new Error('No session available')

    const transitionId = serverPayload.readUInt16BE(0)

    try {
      this.session.processWelcome(serverPayload.subarray(2))

      if (transitionId === 0) {
        this.reinitializing = false
        this.lastTransitionId = transitionId
      } else {
        this.pendingTransition = {
          transition_id: transitionId,
          protocol_version: this.protocolVersion
        }
      }

      return { transitionId, success: true }
    } catch (error) {
      this.recoverFromInvalidTransition(transitionId)
      return { transitionId, success: false }
    }
  }

  encrypt(packet) {
    if (packet.equals(OPUS_SILENCE_FRAME)) return packet
    if (this.protocolVersion === 0 || !this.session?.ready) return packet

    try {
      const encrypted = this.session.encryptOpus(packet)
      return encrypted
    } catch (error) {
      return packet
    }
  }

  decrypt(packet, userId) {
    if (packet.equals(OPUS_SILENCE_FRAME)) return packet

    const canDecrypt =
      this.session?.ready &&
      (this.protocolVersion !== 0 || this.session?.canPassthrough(userId))

    if (!canDecrypt || !this.session) return packet

    try {
      const buffer = this.session.decrypt(
        userId,
        this.MLS.MediaType.AUDIO,
        packet
      )
      this.consecutiveFailures = 0
      return buffer
    } catch (error) {
      if (!this.reinitializing && !this.pendingTransition) {
        this.consecutiveFailures++

        if (this.consecutiveFailures > this.failureTolerance) {
          if (this.lastTransitionId !== undefined) {
            this.recoverFromInvalidTransition(this.lastTransitionId)
          } else {
            throw error
          }
        }
      }
    }

    return null
  }

  destroy() {
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

    this.state = { status: 'disconnected' }
    this.playerState = { status: 'idle' }

    this.sessionId = null
    this.voiceServer = null

    this.hbInterval = null
    this.udpInfo = null
    this.udp = null

    this.ping = -1
    this.statistics = { packetsSent: 0, packetsLost: 0, packetsExpected: 0 }

    this.player = {
      sequence: 0,
      timestamp: 0,
      nextPacket: 0,
      lastPacketTime: null
    }

    this.nonce = 0
    this.nonceBuffer =
      this.encryption === 'aead_aes256_gcm_rtpsize'
        ? Buffer.alloc(12)
        : Buffer.alloc(24)
    this.packetBuffer = Buffer.allocUnsafe(12)

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
  }

  _updateState(state) {
    this.emit('stateChange', this.state, state)
    this.state = state
  }

  _updatePlayerState(state) {
    this.emit('playerStateChange', this.playerState, state)
    this.playerState = state
  }

  _wsSendJSON(op, d) {
    if (!this.ws) return
    const payload = JSON.stringify({ op, d })
    this.ws.send(payload)
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

    const sequenceNumber = buf.readUInt16BE(0)
    const opcode = buf.readUInt8(2)
    const payload = buf.subarray(3)

    this.lastSequence = sequenceNumber

    return { sequenceNumber, opcode, payload }
  }

  _initMLSSessionIfNeeded(protocolVersionHint) {
    if (!MLS) return

    if (!this.channelId) {
      // Silently skip DAVE support when channelId is not set
      return
    }

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

  _ensureKeyPackageSent(reason) {
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
      }
    } catch (e) {
      // Failed to send key package
    }
  }

  _drainBufferedProposals() {
    if (!this.mlsSession) return
    if (!this.mlsSession.externalSenderSet) return
    if (this.pendingProposals.length === 0) return

    while (this.pendingProposals.length > 0) {
      const payload = this.pendingProposals.shift()

      try {
        const connected = new Set(this.connectedUserIds)
        connected.add(String(this.userId))

        const response = this.mlsSession.processProposals(payload, connected)
        if (response) {
          this._wsSendBinary(DAVE_OPCODES.COMMIT_WELCOME, response)
        }
      } catch (e) {
        // Ignoring proposals
      }
    }
  }

  udpSend(data, cb) {
    if (!this.udp) return
    if (!cb)
      cb = (error) => {
        if (error) this.emit('error', error)
      }
    this.udp.send(data, this.udpInfo.port, this.udpInfo.ip, cb)
  }

  _setSpeaking(value) {
    if (!this.ws || !this.udpInfo) return
    this._wsSendJSON(5, { speaking: value, delay: 0, ssrc: this.udpInfo.ssrc })
  }

  _ipDiscovery() {
    return new Promise((resolve) => {
      this.udp.once('message', (message) => {
        const data = message.readUInt16BE(0)
        if (data !== 2) return

        const packet = Buffer.from(message)
        resolve({
          ip: packet.subarray(8, packet.indexOf(0, 8)).toString('utf8'),
          port: packet.readUInt16BE(packet.length - 2)
        })
      })

      const discoveryBuffer = Buffer.alloc(74)
      discoveryBuffer.writeUInt16BE(1, 0)
      discoveryBuffer.writeUInt16BE(70, 2)
      discoveryBuffer.writeUInt32BE(this.udpInfo.ssrc, 4)

      this.udpSend(discoveryBuffer)
    })
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
          max_dave_protocol_version: this.channelId ? this.mlsProtocolVersion : 0
        })
      }
    })

    this.ws.on('message', async (data) => {
      if (typeof data === 'string') {
        let payload
        try {
          payload = JSON.parse(data)
        } catch {
          return
        }
        if (typeof payload.seq === 'number') this.lastSequence = payload.seq
        return this._handleJSON(payload, cb)
      }

      const buf = toNodeBuffer(data)
      if (!buf) return

      const maybeJSON = tryParseJSONFromBuffer(buf)
      if (maybeJSON) {
        if (typeof maybeJSON.seq === 'number') this.lastSequence = maybeJSON.seq
        return this._handleJSON(maybeJSON, cb)
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
              this._drainBufferedProposals()
            } catch (e) {
              this.emit(
                'error',
                new Error(`[DAVE] Failed to set external sender: ${e.message}`)
              )
            }
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
            this.pendingProposals.push(payload)
            break
          }

          try {
            const connected = new Set(this.connectedUserIds)
            connected.add(String(this.userId))

            const response = this.mlsSession.processProposals(
              payload,
              connected
            )
            if (response) {
              this._wsSendBinary(DAVE_OPCODES.COMMIT_WELCOME, response)
            }
          } catch (e) {
            // Ignoring proposals
          }

          break
        }

        case DAVE_OPCODES.ANNOUNCE_COMMIT: {
          if (!this.mlsSession) break

          try {
            const result = this.mlsSession.processCommit(payload)
            if (result.success) {
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
            if (result.success) {
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
          if (data.length <= 12 || data.readUInt8(1) !== 0x78) return

          const ssrc = data.readUInt32BE(8)
          const userData = ssrcs[ssrc]
          if (!userData || !this.udpInfo.secretKey) return

          const rtpVersion = data[0] >> 6
          if (rtpVersion !== 2) return

          const hasPadding = !!(data[0] & 0b100000)
          const hasExtension = !!(data[0] & 0b10000)
          const cc = data[0] & 0b1111
          const nonce =
            this.encryption === 'aead_aes256_gcm_rtpsize'
              ? Buffer.alloc(12)
              : Buffer.alloc(24)
          data.copy(nonce, 0, data.length - 4, data.length)

          let headerSize = 12 + cc * 4
          let extensionLengthInWords = 0

          if (hasExtension) {
            if (data.readUInt16BE(headerSize) !== 0xbede) return
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
              decryptedPacket = Buffer.concat([
                decipher.update(encrypted),
                decipher.final()
              ])
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
              decryptedPacket = Buffer.from(
                Sodium.crypto_aead_xchacha20_poly1305_ietf_decrypt(
                  encrypted,
                  header,
                  nonce,
                  this.udpInfo.secretKey
                )
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

          if (hasPadding) {
            const paddingAmount = decryptedPacket.readUInt8(
              decryptedPacket.length - 1
            )
            if (paddingAmount < decryptedPacket.length)
              decryptedPacket = decryptedPacket.subarray(
                0,
                decryptedPacket.length - paddingAmount
              )
          }

          const extensionDataLength = extensionLengthInWords * 4
          if (hasExtension && extensionDataLength > 0)
            decryptedPacket = decryptedPacket.subarray(extensionDataLength)

          let packet = decryptedPacket

          if (this.mlsSession && userData.userId) {
            const decrypted = this.mlsSession.decrypt(packet, userData.userId)
            if (decrypted !== null) packet = decrypted
            else return
          }

          if (packet.equals(OPUS_SILENCE_FRAME)) {
            if (userData.stream._readableState.ended) return
            this.emit('speakEnd', userData.userId, ssrc)
            userData.stream.push(null)
          } else {
            if (userData.stream._readableState.ended) {
              userData.stream = new PassThrough({ objectMode: true })
              this.emit('speakStart', userData.userId, ssrc)
            }
            userData.stream.write(packet)
          }
        })

        this.udp.on('error', (error) => this.emit('error', error))

        this.udp.on('close', () => {
          if (!this.ws) return
          this._destroy({ status: 'disconnected' })
        })

        const serverInfo = await this._ipDiscovery()

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
        if (payload.d.mode && payload.d.mode !== this.encryption) {
          this.encryption = payload.d.mode
          this.nonceBuffer =
            this.encryption === 'aead_aes256_gcm_rtpsize'
              ? Buffer.alloc(12)
              : Buffer.alloc(24)
        }

        this.udpInfo.secretKey = Buffer.from(payload.d.secret_key)

        if (cb) cb()

        this._updateState({ status: 'connected' })
        this._updatePlayerState({ status: 'idle', reason: 'connected' })

        const serverVersion = payload.d.dave_protocol_version ?? 0

        if (MLS) {
          this.mlsProtocolVersion = Math.min(
            serverVersion,
            MLS_PROTOCOL_VERSION
          )

          if (serverVersion > 0) {
            this._initMLSSessionIfNeeded(this.mlsProtocolVersion)
            this._ensureKeyPackageSent('op4 select_protocol_ack')
          }
        }

        break
      }

      case 5: {
        ssrcs[payload.d.ssrc] = {
          userId: payload.d.user_id,
          stream:
            ssrcs[payload.d.ssrc]?.stream ??
            new PassThrough({ objectMode: true })
        }
        this.emit('speakStart', payload.d.user_id, payload.d.ssrc)
        break
      }

      case 6: {
        this.ping = Date.now() - payload.d.t
        break
      }

      case 8: {
        this.hbInterval = setInterval(() => {
          this._wsSendJSON(3, { t: Date.now(), seq_ack: this.lastSequence })
        }, payload.d.heartbeat_interval)

        break
      }

      case 9: {
        break
      }

      case 11: {
        const ids = payload.d?.user_ids ?? []
        for (const id of ids) this.connectedUserIds.add(String(id))
        break
      }

      case 13: {
        const id = payload.d?.user_id
        if (id) this.connectedUserIds.delete(String(id))
        break
      }

      case DAVE_OPCODES.PREPARE_TRANSITION: {
        if (payload.d?.protocol_version > 0 && !this.mlsSession) {
          this._initMLSSessionIfNeeded(payload.d.protocol_version)
          this._ensureKeyPackageSent('op21 prepare_transition')
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
            if (payload.d?.epoch === 1)
              this._ensureKeyPackageSent('op24 epoch=1')
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

  sendAudioChunk(chunk) {
    if (!this.udpInfo || !this.udpInfo.secretKey) return

    if (this.mlsSession) {
      chunk = this.mlsSession.encrypt(chunk)
    }

    this.packetBuffer.writeUInt8(0x80, 0)
    this.packetBuffer.writeUInt8(0x78, 1)
    this.packetBuffer.writeUInt16BE(this.player.sequence, 2)
    this.packetBuffer.writeUInt32BE(this.player.timestamp, 4)
    this.packetBuffer.writeUInt32BE(this.udpInfo.ssrc, 8)

    this.player.timestamp += TIMESTAMP_INCREMENT
    if (this.player.timestamp >= MAX_TIMESTAMP) this.player.timestamp = 0

    this.player.sequence++
    if (this.player.sequence === MAX_SEQUENCE) this.player.sequence = 0

    this.nonce++
    if (this.nonce === MAX_NONCE) this.nonce = 0

    this.nonceBuffer.fill(0)
    this.nonceBuffer.writeUInt32BE(this.nonce, 0)
    const noncePadding = this.nonceBuffer.subarray(0, 4)

    let encryptedVoice = null

    switch (this.encryption) {
      case 'aead_aes256_gcm_rtpsize': {
        const cipher = crypto.createCipheriv(
          'aes-256-gcm',
          this.udpInfo.secretKey,
          this.nonceBuffer
        )
        cipher.setAAD(this.packetBuffer)
        encryptedVoice = Buffer.concat([
          cipher.update(chunk),
          cipher.final(),
          cipher.getAuthTag()
        ])
        break
      }

      case 'aead_xchacha20_poly1305_rtpsize': {
        encryptedVoice = Buffer.from(
          Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            chunk,
            this.packetBuffer,
            this.nonceBuffer,
            this.udpInfo.secretKey
          )
        )
        break
      }

      default:
        return
    }

    const packet = Buffer.concat([
      this.packetBuffer,
      encryptedVoice,
      noncePadding
    ])
    this.player.lastPacketTime = Date.now()

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
        oldAudioStream.removeListener('finishBuffering', this._markAsStoppable)
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

    for (let i = 0; i < 5; i++) this.sendAudioChunk(OPUS_SILENCE_FRAME)
    this._wsSendJSON(5, {
      speaking: 0,
      delay: 0,
      ssrc: this.udpInfo?.ssrc ?? 0
    })
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
    this.audioStream.canStop = true
  }

  _packetInterval() {
    this.playTimeout = setTimeout(
      () => {
        if (!this.audioStream) return

        const now = Date.now()
        if (this.player.nextPacket < now - 60) this.player.nextPacket = now

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
        } else {
          if (!this.challengeTimeout) {
            this.challengeTimeout = setTimeout(() => {
              this.emit('stuck')
              this.challengeTimeout = null
              this.pause('stuck')
            }, 2000)
          }
        }

        this.player.nextPacket += OPUS_FRAME_DURATION
        this._packetInterval()
      },
      Math.max(0, this.player.nextPacket - Date.now())
    )
  }

  unpause(reason) {
    this._updatePlayerState({ status: 'playing', reason: reason ?? 'unpaused' })
    this._setSpeaking(1 << 0)

    const now = Date.now()
    if (this.player.lastPacketTime) {
      const gap = now - this.player.lastPacketTime
      if (gap > OPUS_FRAME_DURATION * 2) {
        const lostframes = Math.floor(gap / OPUS_FRAME_DURATION)
        const lostTimestamp = lostframes * TIMESTAMP_INCREMENT
        this.player.timestamp =
          (this.player.timestamp + lostTimestamp) % MAX_TIMESTAMP
      }
    }

    this.player.nextPacket = now + OPUS_FRAME_DURATION
    this._packetInterval()

    if (!this.audioStream.canStop)
      this.audioStream.once('finishBuffering', () => this._markAsStoppable())
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
    if (this.connectTimeout) {
      clearTimeout(this.connectTimeout)
      this.connectTimeout = null
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
        if (!ws.closing) ws.close(code, reason)
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

    this._updateState(state)
    this._updatePlayerState({ status: 'idle', reason: 'destroyed' })
  }

  destroy() {
    this._destroy({ status: 'destroyed' }, true)
  }

  voiceStateUpdate(obj) {
    const sid = obj.session_id ?? obj.sessionId
    this.sessionId = sid
  }

  voiceServerUpdate(obj) {
    const endpoint = obj.endpoint
    const token = obj.token
    const channelId = obj.channel_id ?? obj.channelId

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
