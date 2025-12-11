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
const MAX_NONCE = 2 ** 32
const MAX_TIMESTAMP = 2 ** 32
const MAX_SEQUENCE = 2 ** 16

const TRANSITION_EXPIRY = 10
const TRANSITION_EXPIRY_PENDING_DOWNGRADE = 24
const DEFAULT_DECRYPTION_FAILURE_TOLERANCE = 36

const RTP_HEADER_VERSION = 0x80
const RTP_TYPE = 0x78

const DISCORD_CLOSE_CODES = {
  1006: { reconnect: true },
  4014: { error: false },
  4015: { reconnect: true }
}

const ssrcs = {}

const _utils = {
  createStats: () => ({ packetsSent: 0, packetsLost: 0, packetsExpected: 0 }),
  createPlayer: () => ({ sequence: 0, timestamp: 0, nextPacket: 0 }),
  error: (emitter, context, err) =>
    emitter.emit('error', new Error(`[Voice] ${context}: ${err.message}`))
}

class VoiceMLS extends EventEmitter {
  constructor(protocolVersion, userId, channelId, MLSLib, options = {}) {
    super()
    if (!MLSLib)
      throw new Error('MLS library (@snazzah/davey) required but missing')

    this.MLS = MLSLib
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
    this.reinit()
  }

  get voicePrivacyCode() {
    return this.protocolVersion > 0 && this.session?.voicePrivacyCode
      ? this.session.voicePrivacyCode
      : null
  }

  async getVerificationCode(userId) {
    if (!this.session) throw new Error('Session not available')
    return this.session.getVerificationCode(userId)
  }

  reinit() {
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
      this.emit('keyPackage', this.session.getSerializedKeyPackage())
    } else if (this.session) {
      this.session.reset()
      this.session.setPassthroughMode(true, TRANSITION_EXPIRY)
    }
  }

  setExternalSender(externalSender) {
    if (this.session) this.session.setExternalSender(externalSender)
  }

  prepareTransition(data) {
    this.pendingTransition = data
    if (data.transition_id === 0) {
      this.executeTransition(data.transition_id)
      return false
    }
    if (data.protocol_version === 0) {
      this.session?.setPassthroughMode(
        true,
        TRANSITION_EXPIRY_PENDING_DOWNGRADE
      )
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
        this.session?.setPassthroughMode(true, TRANSITION_EXPIRY)
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
      this.reinit()
    }
  }

  recoverFromInvalidTransition(transitionId) {
    if (this.reinitializing) return
    this.reinitializing = true
    this.consecutiveFailures = 0
    this.emit('invalidateTransition', transitionId)
    this.reinit()
  }

  processProposals(payload, connectedClients) {
    if (!this.session) throw new Error('No session')
    const optype = payload.readUInt8(0)
    const { commit, welcome } = this.session.processProposals(
      optype,
      payload.subarray(1),
      [...connectedClients]
    )
    if (!commit) return
    return welcome ? Buffer.concat([commit, welcome]) : commit
  }

  _processGeneric(payload, method) {
    if (!this.session) throw new Error('No session')
    const transitionId = payload.readUInt16BE(0)
    try {
      this.session[method](payload.subarray(2))
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
    } catch {
      this.recoverFromInvalidTransition(transitionId)
      return { transitionId, success: false }
    }
  }

  processCommit(payload) {
    return this._processGeneric(payload, 'processCommit')
  }
  processWelcome(payload) {
    return this._processGeneric(payload, 'processWelcome')
  }

  encrypt(packet, silenceFrame) {
    if (
      this.protocolVersion === 0 ||
      !this.session?.ready ||
      packet.equals(silenceFrame)
    )
      return packet
    return this.session.encryptOpus(packet)
  }

  decrypt(packet, userId, silenceFrame) {
    const canDecrypt =
      this.session?.ready &&
      (this.protocolVersion !== 0 || this.session?.canPassthrough(userId))
    if (packet.equals(silenceFrame) || !canDecrypt || !this.session)
      return packet

    try {
      const buffer = this.session.decrypt(
        userId,
        this.MLS.MediaType.AUDIO,
        packet
      )
      this.consecutiveFailures = 0
      return buffer
    } catch (err) {
      if (!this.reinitializing && !this.pendingTransition) {
        this.consecutiveFailures++
        if (this.consecutiveFailures > this.failureTolerance) {
          if (this.lastTransitionId)
            this.recoverFromInvalidTransition(this.lastTransitionId)
          else throw err
        }
      }
    }
    return null
  }

  destroy() {
    try {
      this.session?.reset()
    } catch {}
    this.session = null
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
    this.udp = null
    this.udpInfo = null
    this.voiceServer = null
    this.sessionId = null

    this.state = { status: 'disconnected' }
    this.playerState = { status: 'idle' }
    this.statistics = _utils.createStats()
    this.player = _utils.createPlayer()

    this.ping = -1
    this.lastSequence = -1

    this.nonce = 0
    this.nonceBuffer =
      this.encryption === 'aead_aes256_gcm_rtpsize'
        ? Buffer.alloc(12)
        : Buffer.alloc(24)
    this.packetBuffer = Buffer.allocUnsafe(12)

    this.hbInterval = null
    this.playTimeout = null
    this.challengeTimeout = null
    this.audioStream = null
    this._boundMarkAsStoppable = this._markAsStoppable.bind(this)

    this.mlsSession = null
    this.mlsProtocolVersion = 0
    this._ownedSSRCs = new Set()
  }

  udpSend(data, cb) {
    if (!this.udp) return
    this.udp.send(
      data,
      this.udpInfo.port,
      this.udpInfo.ip,
      cb ||
        ((err) => {
          if (err) this.emit('error', err)
        })
    )
  }

  _setSpeaking(value) {
    if (!this.ws || !this.udpInfo) return
    this.ws.send(
      JSON.stringify({
        op: 5,
        d: { speaking: value, delay: 0, ssrc: this.udpInfo.ssrc }
      })
    )
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
    if (!this.channelId)
      return _utils.error(this, 'MLS', { message: 'ChannelId not set' })

    try {
      this.mlsSession = new VoiceMLS(
        this.mlsProtocolVersion,
        this.userId,
        this.channelId,
        MLS
      )

      this.mlsSession.on('error', (err) => this.emit('error', err))
      this.mlsSession.on('keyPackage', (pkg) => {
        this.ws.send(
          JSON.stringify({
            op: 23,
            d: {
              version: this.mlsProtocolVersion,
              key_package: pkg.toString('base64')
            }
          })
        )
      })
      this.mlsSession.on('invalidateTransition', (tId) => {
        this.ws.send(JSON.stringify({ op: 31, d: { transition_id: tId } }))
      })
    } catch (err) {
      _utils.error(this, 'MLS Init', err)
    }
  }

  _ipDiscovery() {
    return new Promise((resolve) => {
      const listener = (msg) => {
        if (msg.readUInt16BE(0) !== 2) return
        this.udp.removeListener('message', listener)
        const packet = Buffer.from(msg)
        resolve({
          ip: packet.subarray(8, packet.indexOf(0, 8)).toString('utf8'),
          port: packet.readUInt16BE(packet.length - 2)
        })
      }

      this.udp.on('message', listener)
      const discoveryBuffer = Buffer.alloc(74)
      discoveryBuffer.writeUInt16BE(1, 0)
      discoveryBuffer.writeUInt16BE(70, 2)
      discoveryBuffer.writeUInt32BE(this.udpInfo.ssrc, 4)
      this.udpSend(discoveryBuffer)
    })
  }

  _handleIncomingUdp(msg) {
    if (msg.length <= 12 || msg[1] !== 0x78) return

    const ssrc = msg.readUInt32BE(8)
    const userData = ssrcs[ssrc]
    if (!userData || !this.udpInfo.secretKey) return
    if (msg[0] >> 6 !== 2) return

    const hasPadding = !!(msg[0] & 0b100000)
    const hasExtension = !!(msg[0] & 0b10000)
    const cc = msg[0] & 0b1111

    const nonceLen = this.encryption === 'aead_aes256_gcm_rtpsize' ? 12 : 24
    const nonce = Buffer.allocUnsafe(nonceLen)

    msg.copy(nonce, 0, msg.length - 4)
    if (nonceLen === 24) nonce.fill(0, 4)

    let headerSize = 12 + cc * 4
    let extLen = 0

    if (hasExtension) {
      if (msg.readUInt16BE(headerSize) !== 0xbede) return
      extLen = msg.readUInt16BE(headerSize + 2)
      headerSize += 4
    }

    const header = msg.subarray(0, headerSize)
    let packet

    try {
      if (this.encryption === 'aead_aes256_gcm_rtpsize') {
        const trailer = 16 + 4
        if (msg.length < headerSize + trailer) return

        const encrypted = msg.subarray(headerSize, msg.length - trailer)
        const authTag = msg.subarray(msg.length - trailer, msg.length - 4)

        const decipher = crypto.createDecipheriv(
          'aes-256-gcm',
          this.udpInfo.secretKey,
          nonce
        )
        decipher.setAAD(header)
        decipher.setAuthTag(authTag)
        packet = Buffer.concat([decipher.update(encrypted), decipher.final()])
      } else if (this.encryption === 'aead_xchacha20_poly1305_rtpsize') {
        packet = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          msg.subarray(headerSize, msg.length - 4),
          header,
          nonce,
          this.udpInfo.secretKey
        )
      } else return
    } catch (e) {
      return
    }

    if (!packet) return

    if (hasPadding) {
      const pad = packet[packet.length - 1]
      if (pad < packet.length) packet = packet.subarray(0, packet.length - pad)
    }

    if (hasExtension && extLen > 0) packet = packet.subarray(extLen * 4)

    if (this.mlsSession && userData.userId) {
      const decrypted = this.mlsSession.decrypt(
        packet,
        userData.userId,
        OPUS_SILENCE_FRAME
      )
      if (decrypted) packet = decrypted
      else return
    }

    const isSilence = packet.compare(OPUS_SILENCE_FRAME) === 0

    if (isSilence) {
      if (userData.stream._readableState.ended) return
      this.emit('speakEnd', userData.userId, ssrc)
      userData.stream.push(null)
    } else {
      if (userData.stream._readableState.ended) {
        userData.stream = new PassThrough()
        this.emit('speakStart', userData.userId, ssrc)
      }
      userData.stream.write(packet)
    }
  }

  connect(cb, reconnection) {
    if (this.ws) {
      this._destroyConnection(1000, 'Normal close')
      this._updateState({
        status: 'disconnected',
        reason: 'closed',
        code: 4014
      })
    }

    this._updateState({ status: 'connecting' })

    this.ws = new WebSocket(`wss://${this.voiceServer.endpoint}/?v=8`, {
      headers: {
        'User-Agent': 'DiscordBot (https://github.com/PerformanC/voice, 2.2.0)'
      }
    })

    this.ws.on('open', () => {
      const payload = {
        op: reconnection ? 7 : 0,
        d: {
          server_id: this.guildId,
          session_id: this.sessionId,
          token: this.voiceServer.token
        }
      }
      if (reconnection) payload.d.seq_ack = this.lastSequence
      else payload.d.user_id = this.userId
      this.ws.send(JSON.stringify(payload))
    })

    this.ws.on('message', async (data) => {
      const payload = JSON.parse(data)
      if (payload.seq) this.lastSequence = payload.seq

      switch (payload.op) {
        case 2:
          this.udpInfo = {
            ssrc: payload.d.ssrc,
            ip: payload.d.ip,
            port: payload.d.port,
            secretKey: null
          }
          this.udp = dgram.createSocket('udp4')
          this.udp.on('message', (msg) => this._handleIncomingUdp(msg))
          this.udp.on('close', () => {
            if (this.ws) this._destroy({ status: 'disconnected' })
          })

          const srv = await this._ipDiscovery()
          this.ws.send(
            JSON.stringify({
              op: 1,
              d: {
                protocol: 'udp',
                data: { address: srv.ip, port: srv.port, mode: this.encryption }
              }
            })
          )
          break

        case 4:
          this.udpInfo.secretKey = new Uint8Array(payload.d.secret_key)
          if (cb) cb()
          this._updateState({ status: 'connected' })

          if (MLS && payload.d.dave_protocol_version > 0) {
            this.mlsProtocolVersion = Math.min(
              payload.d.dave_protocol_version,
              MLS_PROTOCOL_VERSION
            )
            this._initMLSSession()
          }
          break

        case 5:
          const ssrc = payload.d.ssrc
          ssrcs[ssrc] = { userId: payload.d.user_id, stream: new PassThrough() }
          this._ownedSSRCs.add(ssrc)
          this.emit('speakStart', payload.d.user_id, ssrc)
          break

        case 6: {
          this.ping = Date.now() - payload.d.t

          break
        }

        case 8:
          this.hbInterval = setInterval(() => {
            this.ws.send(
              JSON.stringify({
                op: 3,
                d: { t: Date.now(), seq_ack: this.lastSequence }
              })
            )
          }, payload.d.heartbeat_interval)
          break

        case 21:
          if (
            this.mlsSession &&
            payload.d &&
            this.mlsSession.prepareTransition(payload.d)
          ) {
            this.ws.send(
              JSON.stringify({
                op: 22,
                d: { transition_id: payload.d.transition_id }
              })
            )
          }
          break

        case 22:
          this.mlsSession?.executeTransition(payload.d?.transition_id)
          break

        case 24:
          this.mlsSession?.prepareEpoch(payload.d)
          break

        case 25:
          if (this.mlsSession && payload.d?.external_sender_package) {
            try {
              this.mlsSession.setExternalSender(
                Buffer.from(payload.d.external_sender_package, 'base64')
              )
            } catch (e) {
              _utils.error(this, 'Ext Sender', e)
            }
          }
          break

        case 27:
          if (this.mlsSession && payload.d?.proposals) {
            try {
              const clients = new Set(
                Object.values(ssrcs)
                  .map((u) => u.userId)
                  .filter(Boolean)
              )
              const res = this.mlsSession.processProposals(
                Buffer.from(payload.d.proposals, 'base64'),
                clients
              )
              if (res)
                this.ws.send(
                  JSON.stringify({
                    op: 28,
                    d: { commit_message: res.toString('base64') }
                  })
                )
            } catch (e) {
              _utils.error(this, 'Proposals', e)
            }
          }
          break

        case 28:
        case 30:
          if (this.mlsSession && payload.d) {
            const isCommit = payload.op === 28
            const method = isCommit ? 'processCommit' : 'processWelcome'
            const key = isCommit ? 'commit_message' : 'welcome_message'

            try {
              const buf = Buffer.from(payload.d[key], 'base64')
              const full = Buffer.allocUnsafe(buf.length + 2)
              full.writeUInt16BE(payload.d.transition_id, 0)
              buf.copy(full, 2)

              const res = this.mlsSession[method](full)
              if (res.success) {
                this.ws.send(
                  JSON.stringify({
                    op: 22,
                    d: { transition_id: res.transitionId }
                  })
                )
              }
            } catch (e) {
              _utils.error(this, method, e)
            }
          }
          break

        case 31:
          this.mlsSession?.recoverFromInvalidTransition(
            payload.d?.transition_id
          )
          break
      }
    })

    this.ws.on('close', (code, reason) => {
      if (!this.ws) return
      if (DISCORD_CLOSE_CODES[code]?.reconnect) {
        this._destroyConnection(code, reason)
        this._updatePlayerState({ status: 'idle', reason: 'reconnecting' })
        this.connect(() => {
          if (this.audioStream) this.unpause('reconnected')
        }, true)
      } else {
        this._destroy({ status: 'disconnected', reason: 'closed', code }, false)
      }
    })

    this.ws.on('error', (e) => this.emit('error', e))
  }

  sendAudioChunk(chunk) {
    if (!this.udpInfo?.secretKey) return
    if (this.mlsSession)
      chunk = this.mlsSession.encrypt(chunk, OPUS_SILENCE_FRAME)

    this.packetBuffer[0] = RTP_HEADER_VERSION
    this.packetBuffer[1] = RTP_TYPE
    this.packetBuffer.writeUInt16BE(this.player.sequence, 2)
    this.packetBuffer.writeUInt32BE(this.player.timestamp, 4)
    this.packetBuffer.writeUInt32BE(this.udpInfo.ssrc, 8)

    this.player.timestamp =
      (this.player.timestamp + TIMESTAMP_INCREMENT) % MAX_TIMESTAMP
    this.player.sequence = (this.player.sequence + 1) % MAX_SEQUENCE
    this.nonce = (this.nonce + 1) % MAX_NONCE
    this.nonceBuffer.writeUInt32LE(this.nonce, 0)

    let encrypted
    if (this.encryption === 'aead_aes256_gcm_rtpsize') {
      const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        this.udpInfo.secretKey,
        this.nonceBuffer
      )
      cipher.setAAD(this.packetBuffer)
      encrypted = Buffer.concat([
        cipher.update(chunk),
        cipher.final(),
        cipher.getAuthTag()
      ])
    } else if (this.encryption === 'aead_xchacha20_poly1305_rtpsize') {
      encrypted = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        chunk,
        this.packetBuffer,
        this.nonceBuffer,
        this.udpInfo.secretKey
      )
    }

    const packet = Buffer.concat([
      this.packetBuffer,
      encrypted,
      this.nonceBuffer.subarray(0, 4)
    ])
    this.player.lastPacketTime = Date.now()
    this.udpSend(packet, (err) => {
      if (err) this.statistics.packetsLost++
      else this.statistics.packetsSent++
      this.statistics.packetsExpected++
    })
  }

  play(stream) {
    if (!this.udpInfo) {
      _utils.error(this, 'Play', { message: 'No UDP Info' })
      return
    }
    const old = this.audioStream
    stream.once('readable', () => {
      if (old && this.playTimeout) {
        this._clearTimers()
        this.statistics = _utils.createStats()
        old.removeListener('finishBuffering', this._boundMarkAsStoppable)
      }
      this.audioStream = stream
      this.unpause('requested')
    })
    return old
  }

  stop(reason) {
    this._clearTimers()
    if (this.audioStream) {
      this.audioStream.destroy()
      this.audioStream.removeAllListeners()
      this.audioStream = null
    }
    this.statistics = _utils.createStats()
    this._updatePlayerState({ status: 'idle', reason: reason ?? 'stopped' })

    // isso aqui manda 5 frames de silêncio (pq o Discord gosta, zueira, ele reseta os buffers.)
    for (let i = 0; i < 5; i++) {
      this.sendAudioChunk(OPUS_SILENCE_FRAME)
    }

    this._setSpeaking(0)
  }

  pause(reason) {
    this._updatePlayerState({ status: 'idle', reason: reason ?? 'paused' })
    this._setSpeaking(0)
    this._clearTimers()
  }

  _markAsStoppable() {
    if (this.audioStream) this.audioStream.canStop = true
  }

  _clearTimers() {
    if (this.playTimeout) {
      clearTimeout(this.playTimeout)
      this.playTimeout = null
    }
    if (this.challengeTimeout) {
      clearTimeout(this.challengeTimeout)
      this.challengeTimeout = null
    }
  }

  _packetInterval() {
    this.playTimeout = setTimeout(
      () => {
        if (!this.audioStream) return

        // evita o jitter se tiver mt atrasado (mais de 60ms)
        const now = Date.now()
        if (this.player.nextPacket < now - 60) {
          this.player.nextPacket = now
        }

        const chunk = this.audioStream.read(OPUS_FRAME_SIZE)

        if (!chunk && this.audioStream.canStop) {
          this._clearTimers()
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
    this._setSpeaking(1)

    const now = Date.now()

    if (this.player.lastPacketTime) {
      const gap = now - this.player.lastPacketTime

      if (gap > OPUS_FRAME_DURATION * 2) {
        const lostFrames = Math.floor(gap / OPUS_FRAME_DURATION)
        const lostTimestamp = lostFrames * TIMESTAMP_INCREMENT

        this.player.timestamp =
          (this.player.timestamp + lostTimestamp) % MAX_TIMESTAMP
      }
    }
    this.player.nextPacket = now + OPUS_FRAME_DURATION

    this._packetInterval()
    if (!this.audioStream.canStop)
      this.audioStream.once('finishBuffering', this._boundMarkAsStoppable)
  }

  _destroyConnection(code, reason) {
    if (this.hbInterval) {
      clearInterval(this.hbInterval)
      this.hbInterval = null
    }
    this._clearTimers()
    this.player = _utils.createPlayer()
    if (this.ws) {
      this.ws.close(code, reason)
      this.ws.removeAllListeners()
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

    if (this._ownedSSRCs) {
      for (const s of this._ownedSSRCs) delete ssrcs[s]
      this._ownedSSRCs.clear()
    }

    if (this.audioStream && destroyStream) {
      this.audioStream.destroy()
      this.audioStream.removeAllListeners()
      this.audioStream = null
    }
    this.mlsSession?.destroy()
    this.mlsSession = null
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

export default {
  joinVoiceChannel: (obj) => new Connection(obj),
  getSpeakStream: (ssrc) => ssrcs[ssrc]?.stream
}
