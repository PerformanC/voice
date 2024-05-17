import EventEmitter from 'node:events'
import dgram from 'node:dgram'
import { PassThrough } from 'node:stream'

import WebSocket from '@performanc/pwsl'
import Sodium from './sodium.js'

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

const ssrcs = {}

class Connection extends EventEmitter {
  constructor(obj) {
    super()

    this.guildId = obj.guildId
    this.userId = obj.userId
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
    this.nonceBuffer = Buffer.alloc(24)
    this.packetBuffer = Buffer.allocUnsafe(12)

    this.playTimeout = null
    this.audioStream = null
  }

  udpSend(data, cb) {
    if (!cb) cb = (error) => {
      if (error) this.emit('error', error)
    }

    this.udp.send(data, this.udpInfo.port, this.udpInfo.ip, cb)
  }

  _setSpeaking(value) {
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
      discoveryBuffer.writeUInt32BE(this.udp.ssrc, 4)

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

    this.ws = new WebSocket(`wss://${this.voiceServer.endpoint}/?v=4`, {
      headers: {
        'User-Agent': 'DiscordBot (https://github.com/PerformanC/voice, 2.0.5)'
      }
    })

    this.ws.on('open', () => {
      if (reconnection) {
        this.ws.send(JSON.stringify({
          op: 7,
          d: {
            server_id: this.voiceServer.guildId,
            session_id: this.sessionId,
            token: this.voiceServer.token
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

            let dataEnd = null

            switch (this.encryption) {
              case 'xsalsa20_poly1305': {
                dataEnd = data.length
                data.copy(this.nonceBuffer, 0, 0, 12)

                break
              }
              case 'xsalsa20_poly1305_suffix': {
                dataEnd = data.length - 24
                data.copy(this.nonceBuffer, 0, dataEnd)

                break
              }
              case 'xsalsa20_poly1305_lite': {
                dataEnd = data.length - 4
                data.copy(this.nonceBuffer, 0, dataEnd)

                break
              }
            }

            const voice = data.subarray(12, dataEnd)

            let packet = Buffer.from(Sodium.open(voice, this.nonceBuffer, this.udpInfo.secretKey))

            if (packet[0] === 0xbe && packet[1] === 0xde)
              packet = packet.subarray(4 + 4 * packet.readUInt16BE(2))

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
          this.ping = Date.now() - payload.d

          break
        }
        case 8: {
          this.hbInterval = setInterval(() => {
            this.ws.send(JSON.stringify({
              op: 3,
              d: Date.now()
            }))
          }, payload.d.heartbeat_interval)

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

    let packet = null

    switch (this.encryption) {
      case 'xsalsa20_poly1305': {
        const output = Sodium.close(chunk, nonce, this.udpInfo.secretKey)

        packet = Buffer.concat([ this.packetBuffer, output ])

        break
      }
      case 'xsalsa20_poly1305_suffix': {
        const random = Sodium.random(24, this.nonceBuffer)
        const output = Sodium.close(chunk, random, this.udpInfo.secretKey)

        packet = Buffer.concat([ this.packetBuffer, output, random ])

        break
      }
      case 'xsalsa20_poly1305_lite': {
        this.nonce++
        if (this.nonce === MAX_NONCE) this.nonce = 0
        this.nonceBuffer.writeUInt32LE(this.nonce, 0)

        const output = Sodium.close(chunk, this.nonceBuffer, this.udpInfo.secretKey)

        packet = Buffer.concat([ this.packetBuffer, output, this.nonceBuffer.subarray(0, 4) ])

        break
      }
    }

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

    audioStream.once('readable', () => {
      if (this.audioStream && this.playTimeout) {
        this.statistics = {
          packetsSent: 0,
          packetsLost: 0,
          packetsExpected: 0
        }

        this.audioStream = audioStream

        if (!this.audioStream.canStop) {
          this.audioStream.removeListener('finishBuffering', this._markAsStoppable)
          this.audioStream.once('finishBuffering', () => this._markAsStoppable())
        }

        return;
      }

      this.audioStream = audioStream

      this.unpause('requested')
    })
  }

  stop(reason) {
    clearTimeout(this.playTimeout)
    this.playTimeout = null

    this.audioStream.destroy()
    this.audioStream.removeAllListeners()
    this.audioStream = null

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