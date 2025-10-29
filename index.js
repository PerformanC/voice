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
} catch {}

const MLS_PROTOCOL_VERSION = MLS?.DAVE_PROTOCOL_VERSION ?? 0

const nonce = Buffer.alloc(24)
const OPUS_SAMPLE_RATE = 48000
const OPUS_FRAME_DURATION = 20
const OPUS_FRAME_SIZE = OPUS_SAMPLE_RATE * OPUS_FRAME_DURATION / 1000
const OPUS_SILENCE_FRAME = Buffer.from([ 0xf8, 0xff, 0xfe ])
const TIMESTAMP_INCREMENT = (OPUS_SAMPLE_RATE / 100) * 2
const MAX_NONCE = 2 ** 32
const MAX_TIMESTAMP = 2 ** 32
const MAX_SEQUENCE = 2 ** 16
const DISCORD_CLOSE_CODES = {
  1006: { reconnect: true },
  4014: { error: false },
  4015: { reconnect: true }
}
const HEADER_EXTENSION_BYTE = Buffer.from([ 0xbe, 0xde ])
const UNPADDED_NONCE_LENGTH = 4
const AUTH_TAG_LENGTH = 16

const ssrcs = {}

const TRANSITION_EXPIRY = 10
const TRANSITION_EXPIRY_PENDING_DOWNGRADE = 24
const DEFAULT_DECRYPTION_FAILURE_TOLERANCE = 36

class VoiceMLS extends EventEmitter {
  constructor(protocolVersion, userId, channelId, MLS, options = {}) {
    super()

    if (!MLS) {
      throw new Error('MLS library (@snazzah/davey) is required but not available')
    }

    this.MLS = MLS
    this.protocolVersion = protocolVersion
    this.userId = userId
    this.channelId = channelId
    this.lastTransitionId = undefined
    this.pendingTransition = undefined
    this.downgraded = false
    this.consecutiveFailures = 0
    this.reinitializing = false
    this.failureTolerance = options.decryptionFailureTolerance ?? DEFAULT_DECRYPTION_FAILURE_TOLERANCE

    this.session = null
    this.reinit()
  }

  get voicePrivacyCode() {
    if (this.protocolVersion === 0 || !this.session?.voicePrivacyCode) {
      return null
    }
    return this.session.voicePrivacyCode
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
        this.session = new this.MLS.DAVESession(this.protocolVersion, this.userId, this.channelId)
      }
      
      this.emit('keyPackage', this.session.getSerializedKeyPackage())
    } else if (this.session) {
      this.session.reset()
      this.session.setPassthroughMode(true, TRANSITION_EXPIRY)
    }
  }

  setExternalSender(externalSender) {
    if (!this.session) throw new Error('No session available')
    this.session.setExternalSender(externalSender)
  }

  getSerializedKeyPackage() {
    if (!this.session) throw new Error('No session available')
    return this.session.getSerializedKeyPackage()
  }

  prepareTransition(data) {
    this.pendingTransition = data

    if (data.transition_id === 0) {
      this.executeTransition(data.transition_id)
    } else {
      if (data.protocol_version === 0) {
        this.session?.setPassthroughMode(true, TRANSITION_EXPIRY_PENDING_DOWNGRADE)
      }
      return true
    }

    return false
  }

  executeTransition(transitionId) {
    if (!this.pendingTransition) {
      return
    }

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
    } else {
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
    if (!this.session) throw new Error('No session available')
    const optype = payload.readUInt8(0)
    const { commit, welcome } = this.session.processProposals(
      optype,
      payload.subarray(1),
      Array.from(connectedClients)
    )
    if (!commit) return
    return welcome ? Buffer.concat([commit, welcome]) : commit
  }

  processCommit(payload) {
    if (!this.session) throw new Error('No session available')
    const transitionId = payload.readUInt16BE(0)
    try {
      this.session.processCommit(payload.subarray(2))
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

  processWelcome(payload) {
    if (!this.session) throw new Error('No session available')
    const transitionId = payload.readUInt16BE(0)
    try {
      this.session.processWelcome(payload.subarray(2))
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

  encrypt(packet, SILENCE_FRAME) {
    if (this.protocolVersion === 0 || !this.session?.ready || packet.equals(SILENCE_FRAME)) {
      return packet
    }
    return this.session.encryptOpus(packet)
  }

  decrypt(packet, userId, SILENCE_FRAME) {
    const canDecrypt = this.session?.ready && 
      (this.protocolVersion !== 0 || this.session?.canPassthrough(userId))
    
    if (packet.equals(SILENCE_FRAME) || !canDecrypt || !this.session) {
      return packet
    }

    try {
      const buffer = this.session.decrypt(userId, this.MLS.MediaType.AUDIO, packet)
      this.consecutiveFailures = 0
      return buffer
    } catch (error) {
      if (!this.reinitializing && !this.pendingTransition) {
        this.consecutiveFailures++
        if (this.consecutiveFailures > this.failureTolerance) {
          if (this.lastTransitionId) {
            this.recoverFromInvalidTransition(this.lastTransitionId)
          } else {
            throw error
          }
        }
      } else if (this.reinitializing) {
      } else if (this.pendingTransition) {
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
    this.channelId = null
    this.encryption = obj.encryption

    this.ws = null

    this.state = {
      status: 'disconnected'
    }
    this.playerState = {
      status: 'idle'
    }

    this.sessionId = null
    this.voiceServer = null

    this.hbInterval = null
    this.udpInfo = null
    this.udp = null

    this.ping = -1
    this.statistics = {
      packetsSent: 0,
      packetsLost: 0,
      packetsExpected: 0
    }

    this.player = {
      sequence: 0,
      timestamp: 0,
      nextPacket: 0
    }

    this.nonce = 0
    this.nonceBuffer = this.encryption === 'aead_aes256_gcm_rtpsize' ? Buffer.alloc(12) : Buffer.alloc(24)
    this.packetBuffer = Buffer.allocUnsafe(12)

    this.playTimeout = null
    this.audioStream = null

    this.lastSequence = -1

    this.mlsSession = null
    this.mlsProtocolVersion = 0
  }

  udpSend(data, cb) {
    if (!this.udp) return;

    if (!cb) cb = (error) => {
      if (error) this.emit('error', error)
    }

    this.udp.send(data, this.udpInfo.port, this.udpInfo.ip, cb)
  }

  _setSpeaking(value) {
    if (!this.ws || !this.udpInfo) return

    this.ws.send(JSON.stringify({
      op: 5,
      d: {
        speaking: value,
        delay: 0,
        ssrc: this.udpInfo.ssrc
      }
    }))
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
    if (!MLS || this.mlsProtocolVersion === 0) {
      return
    }

    if (!this.channelId) {
      this.emit('error', new Error('[MLS] Cannot initialize - channelId not set. Call voiceServerUpdate first.'))
      return
    }

    try {
      const useVersion = this.mlsProtocolVersion
      
      this.mlsSession = new VoiceMLS(
        useVersion, 
        this.userId, 
        this.channelId,
        MLS
      )

      this.mlsSession.on('error', (err) => this.emit('error', err))
      this.mlsSession.on('keyPackage', (keyPackage) => {
        this.ws.send(JSON.stringify({
          op: 23,
          d: {
            version: useVersion,
            key_package: keyPackage.toString('base64')
          }
        }))
      })
      this.mlsSession.on('invalidateTransition', (transitionId) => {
        this.ws.send(JSON.stringify({
          op: 31,
          d: {
            transition_id: transitionId
          }
        }))
      })
    } catch (error) {
      this.emit('error', new Error(`[MLS] Failed to initialize session: ${error.message}`))
    }
  }

  _ipDiscovery() {
    return new Promise((resolve) => {
      this.udp.once('message', (message) => {
        const data = message.readUInt16BE(0)
        if (data !== 2) return;

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

      this._updateState({ status: 'disconnected', reason: 'closed', code: 4014, closeReason: 'Disconnected.' }) 
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
        this.ws.send(JSON.stringify({
          op: 7,
          d: {
            server_id: this.guildId,
            session_id: this.sessionId,
            token: this.voiceServer.token,
            seq_ack: this.lastSequence
          }
        }))
      } else {
        this.ws.send(JSON.stringify({
          op: 0,
          d: {
            server_id: this.guildId,
            user_id: this.userId,
            session_id: this.sessionId,
            token: this.voiceServer.token
          }
        }))
      }
    })

    this.ws.on('message', async (data) => {
      const payload = JSON.parse(data)

      if (payload.seq) this.lastSequence = payload.seq

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
            if (data.length <= 8) return;

            const ssrc = data.readUInt32BE(8)
            const userData = ssrcs[ssrc]

            if (!userData || !this.udpInfo.secretKey) return;

            data.copy(this.nonceBuffer, 0, data.length - UNPADDED_NONCE_LENGTH, data.length)

            let headerSize = 12
            const first = data.readUint8()
            if ((first >> 4) & 0x01) headerSize += 4

            const header = data.subarray(0, headerSize)

            const encrypted = data.subarray(headerSize, data.length - AUTH_TAG_LENGTH - UNPADDED_NONCE_LENGTH)
            const authTag = data.subarray(
              data.length - AUTH_TAG_LENGTH - UNPADDED_NONCE_LENGTH,
              data.length - UNPADDED_NONCE_LENGTH
            )

            let packet = null
            switch (this.encryption) {
              case 'aead_aes256_gcm_rtpsize': {
                const decipheriv = crypto.createDecipheriv('aes-256-gcm', this.udpInfo.secretKey, this.nonceBuffer)
                decipheriv.setAAD(header)
                decipheriv.setAuthTag(authTag)
        
                packet = Buffer.concat([ decipheriv.update(encrypted), decipheriv.final() ])
                break
              }
              case 'aead_xchacha20_poly1305_rtpsize': {
                packet = Buffer.from(
                  Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    Buffer.concat([ encrypted, authTag ]),
                    header,
                    this.nonceBuffer,
                    this.udpInfo.secretKey
                  )
                )
              }
            }

            if (data.subarray(12, 14).compare(HEADER_EXTENSION_BYTE) === 0) {
              const headerExtensionLength = data.subarray(14).readUInt16BE()
              packet = packet.subarray(4 * headerExtensionLength)
            }

            if (this.mlsSession && userData.userId) {
              const decrypted = this.mlsSession.decrypt(packet, userData.userId, OPUS_SILENCE_FRAME)
              if (decrypted !== null) {
                packet = decrypted
              } else {
                return
              }
            }

            if (packet.compare(OPUS_SILENCE_FRAME) === 0) {
              if (userData.stream._readableState.ended) return;

              this.emit('speakEnd', userData.userId, ssrc)

              userData.stream.push(null)
            } else {
              if (userData.stream._readableState.ended) {
                userData.stream = new PassThrough()

                this.emit('speakStart', userData.userId, ssrc)
              }

              userData.stream.write(packet)
            }
          })

          this.udp.on('error', (error) => this.emit('error', error))

          this.udp.on('close', () => {
            if (!this.ws) return;

            this._destroy({ status: 'disconnected' })
          })

          const serverInfo = await this._ipDiscovery()

          this.ws.send(JSON.stringify({
            op: 1,
            d: {
              protocol: 'udp',
              data: {
                address: serverInfo.ip,
                port: serverInfo.port,
                mode: this.encryption
              }
            }
          }))

          break
        }
        case 4: {
          this.udpInfo.secretKey = new Uint8Array(payload.d.secret_key)

          if (cb) cb()

          this._updateState({ status: 'connected' })
          this._updatePlayerState({ status: 'idle', reason: 'connected' })

          const serverSupportsMLS = payload.d.dave_protocol_version && payload.d.dave_protocol_version > 0
          
          if (MLS && serverSupportsMLS) {
            this.mlsProtocolVersion = Math.min(payload.d.dave_protocol_version, MLS_PROTOCOL_VERSION)
            this._initMLSSession()
          }

          break
        }
        case 5: {
          ssrcs[payload.d.ssrc] = {
            userId: payload.d.user_id,
            stream: new PassThrough()
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
            this.ws.send(JSON.stringify({
              op: 3,
              d: {
                t: Date.now(),
                seq_ack: this.lastSequence
              }
            }))
          }, payload.d.heartbeat_interval)

          break
        }
        case 24: {
          if (this.mlsSession && payload.d?.external_sender_package) {
            try {
              const buffer = Buffer.from(payload.d.external_sender_package, 'base64')
              this.mlsSession.setExternalSender(buffer)
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to set external sender: ${error.message}`))
            }
          }
          break
        }
        case 25: {
          if (this.mlsSession && payload.d) {
            try {
              const shouldSignal = this.mlsSession.prepareTransition(payload.d)
              if (shouldSignal) {
                this.ws.send(JSON.stringify({
                  op: 26,
                  d: {
                    transition_id: payload.d.transition_id
                  }
                }))
              }
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to prepare transition: ${error.message}`))
            }
          }
          break
        }
        case 26: {
          if (this.mlsSession && payload.d?.transition_id !== undefined) {
            try {
              this.mlsSession.executeTransition(payload.d.transition_id)
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to execute transition: ${error.message}`))
            }
          }
          break
        }
        case 27: {
          if (this.mlsSession && payload.d) {
            try {
              const transitionId = payload.d.transition_id
              const buffer = Buffer.from(payload.d.commit_message, 'base64')
              const fullBuffer = Buffer.allocUnsafe(buffer.length + 2)
              fullBuffer.writeUInt16BE(transitionId, 0)
              buffer.copy(fullBuffer, 2)
              
              const result = this.mlsSession.processCommit(fullBuffer)
              if (result.success) {
                this.ws.send(JSON.stringify({
                  op: 26,
                  d: {
                    transition_id: result.transitionId
                  }
                }))
              }
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to process commit: ${error.message}`))
            }
          }
          break
        }
        case 28: {
          if (this.mlsSession && payload.d) {
            try {
              const transitionId = payload.d.transition_id
              const buffer = Buffer.from(payload.d.welcome_message, 'base64')
              const fullBuffer = Buffer.allocUnsafe(buffer.length + 2)
              fullBuffer.writeUInt16BE(transitionId, 0)
              buffer.copy(fullBuffer, 2)
              
              const result = this.mlsSession.processWelcome(fullBuffer)
              if (result.success) {
                this.ws.send(JSON.stringify({
                  op: 26,
                  d: {
                    transition_id: result.transitionId
                  }
                }))
              }
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to process welcome: ${error.message}`))
            }
          }
          break
        }
        case 29: {
          if (this.mlsSession && payload.d?.proposals) {
            try {
              const proposals = Buffer.from(payload.d.proposals, 'base64')
              
              const connectedClients = new Set(Object.keys(ssrcs).map(ssrc => ssrcs[ssrc]?.userId).filter(Boolean))
              
              const response = this.mlsSession.processProposals(proposals, connectedClients)
              if (response) {
                this.ws.send(JSON.stringify({
                  op: 28,
                  d: {
                    commit_message: response.toString('base64')
                  }
                }))
              }
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to process proposals: ${error.message}`))
            }
          }
          break
        }
        case 30: {
          if (this.mlsSession && payload.d) {
            try {
              this.mlsSession.prepareEpoch(payload.d)
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to prepare epoch: ${error.message}`))
            }
          }
          break
        }
        case 31: {
          if (this.mlsSession && payload.d?.transition_id !== undefined) {
            try {
              this.mlsSession.recoverFromInvalidTransition(payload.d.transition_id)
            } catch (error) {
              this.emit('error', new Error(`[MLS] Failed to recover from invalid transition: ${error.message}`))
            }
          }
          break
        }
      }
    })

    this.ws.on('close', (code, reason) => {
      if (!this.ws) return;

      const closeCode = DISCORD_CLOSE_CODES[code]

      if (closeCode?.reconnect) {
        this._destroyConnection(code, reason)

        this._updatePlayerState({ status: 'idle', reason: 'reconnecting' })

        this.connect(() => {
          if (this.audioStream) this.unpause('reconnected')
        }, true)
      } else {
        this._destroy({ status: 'disconnected', reason: 'closed', code, closeReason: reason }, false)

        return;
      }
    })

    this.ws.on('error', (error) => this.emit('error', error))
  }

  sendAudioChunk(chunk) {
    if (!this.udpInfo || !this.udpInfo.secretKey) return;

    if (this.mlsSession) {
      chunk = this.mlsSession.encrypt(chunk, OPUS_SILENCE_FRAME)
    }

    this.packetBuffer.writeUInt8(0x80, 0)
    this.packetBuffer.writeUInt8(0x78, 1)

    this.packetBuffer.writeUInt16BE(this.player.sequence, 2, 2)
    this.packetBuffer.writeUInt32BE(this.player.timestamp, 4, 4)
    this.packetBuffer.writeUInt32BE(this.udpInfo.ssrc, 8, 4)

    this.packetBuffer.copy(nonce, 0, 0, 12)

    this.player.timestamp += TIMESTAMP_INCREMENT
    if (this.player.timestamp >= MAX_TIMESTAMP) this.player.timestamp = 0
    this.player.sequence++
    if (this.player.sequence === MAX_SEQUENCE) this.player.sequence = 0

    this.nonce++
    if (this.nonce === MAX_NONCE) this.nonce = 0
    this.nonceBuffer.writeUInt32LE(this.nonce, 0)

    const noncePadding = this.nonceBuffer.subarray(0, 4)

    let encryptedVoice = null
    switch (this.encryption) {
      case 'aead_aes256_gcm_rtpsize': {
        const cipher = crypto.createCipheriv('aes-256-gcm', this.udpInfo.secretKey, this.nonceBuffer)
				cipher.setAAD(this.packetBuffer)

        encryptedVoice = Buffer.concat([ cipher.update(chunk), cipher.final(), cipher.getAuthTag() ])

        break
      }
      case 'aead_xchacha20_poly1305_rtpsize': {
				encryptedVoice = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
					chunk,
					this.packetBuffer,
					this.nonceBuffer,
					this.udpInfo.secretKey,
				)
			}
    }

    const packet = Buffer.concat([ this.packetBuffer, encryptedVoice, noncePadding ])

    this.udpSend(packet, (error) => {
      if (error) this.statistics.packetsLost++
      else this.statistics.packetsSent++

      this.statistics.packetsExpected++
    })
  }

  play(audioStream) {
    if (!this.udpInfo) {
      this.emit('error', new Error('Cannot play audio without UDP info.'))

      return;
    }

    const oldAudioStream = this.audioStream;

    audioStream.once('readable', () => {
      if (oldAudioStream && this.playTimeout) {
        clearTimeout(this.playTimeout);
        this.playTimeout = null;

        this.statistics = {
          packetsSent: 0,
          packetsLost: 0,
          packetsExpected: 0
        };

        oldAudioStream.removeListener('finishBuffering', this._markAsStoppable);
      }
      
      this.audioStream = audioStream;
      this.unpause('requested');
    });

    return oldAudioStream;
  }

  stop(reason) {
    clearTimeout(this.playTimeout)
    this.playTimeout = null

    if(this.audioStream) {
      this.audioStream.destroy()
      this.audioStream.removeAllListeners()
      this.audioStream = null
    }

    this.statistics = {
      packetsSent: 0,
      packetsLost: 0,
      packetsExpected: 0
    }

    this._updatePlayerState({ status: 'idle', reason: reason ?? 'stopped' })

    this.udpSend(OPUS_SILENCE_FRAME)

    this._setSpeaking(0)
  }

  pause(reason) {
    this._updatePlayerState({ status: 'idle', reason: reason ?? 'paused' })

    this._setSpeaking(0)
    clearTimeout(this.playTimeout)
  }

  _markAsStoppable() {
    this.audioStream.canStop = true
  }

  _packetInterval() {
    this.playTimeout = setTimeout(() => {
      if(!this.audioStream) return;
      const chunk = this.audioStream.read(OPUS_FRAME_SIZE)

      if (!chunk && this.audioStream.canStop) return this.stop('finished')

      if (chunk) this.sendAudioChunk(chunk)
    
      this.player.nextPacket += OPUS_FRAME_DURATION
      this._packetInterval()
    }, this.player.nextPacket - Date.now())
  }

  unpause(reason) {
    this._updatePlayerState({ status: 'playing', reason: reason ?? 'unpaused' })

    this._setSpeaking(1 << 0)

    this.player.nextPacket = Date.now() + OPUS_FRAME_DURATION
    this._packetInterval()
    
    if (!this.audioStream.canStop) this.audioStream.once('finishBuffering', () => this._markAsStoppable())
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

    this.player = {
      sequence: 0,
      timestamp: 0,
      nextPacket: 0
    }

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
    if (this.voiceServer?.token === obj.token && this.voiceServer?.endpoint === obj.endpoint) return;

    if (obj.channel_id) {
      this.channelId = obj.channel_id
    }

    this.voiceServer = {
      token: obj.token,
      endpoint: obj.endpoint
    }
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
