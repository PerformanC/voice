# @performanc/voice

Performant Discord voice API client for ES6 Node.js

## Features

- Dependency-free
- Lightweight
- Stable

## Installation

### Release

```shell
$ npm install @performanc/voice
```

### Development

```shell
$ npm install github:PerformanC/voice
```

## Usage

```javascript
import perfcVoice from '@performanc/voice'

...

const guildId = '123123123'
const userId = '123123123'

const connection =  perfcVoice.joinVoiceChannel({ guildId, userId, encryption: 'xsalsa20_poly1305_lite' })

client.ws.on('VOICE_STATE_UPDATE', (data) => {
  if (data.guild_id == guildId && data.user_id == userId) {
    connection.voiceStateUpdate({
      sessionId: data.session_id
    })
  }
})

client.ws.on('VOICE_SERVER_UPDATE', (data) => {
  if (data.guild_id == guildId && data.user_id == userId) {
    connection.voiceServerUpdate({
      token: data.token,
      endpoint: data.endpoint
    })
  }
})

connection.on('stateChange', (_oldState, newState) => {
  if (newState.status == 'ready')
    console.log('Voice connection ready')
})

connection.on('playerStateChange', (_oldState, newState) => {
  if (newState.status === 'idle' && newState.reason === 'finished')
    console.log('End of audio')

  if (newState.status == 'playing' && newState.reason === 'requested')
    console.log('Playing audio')
})

connection.connect(() => connection.play(stream))
```

## Documentation

Hand-written documentation for all public methods, properties and functions can be found in the [docs folder](docs/).

## Troubleshoot

### Audio not playing

@performanc/voice doesn't modify the audio stream in any way except for the encryption which is mandatory for Discord voice connections. If the audio is not playing, it is most likely an issue with the audio stream itself. Make sure the audio stream is valid and is not empty.

The audio stream must be a opus encoded audio stream, 48kHz, 2 channels, 20ms frame size. If the audio stream is not in this format, it must be converted to this format before being played.

### Error: Session no longer valid

This error can occur even when the data is correct. This happens when Discord doesn't recognize that the last websocket session has been closed. This can be fixed by waiting for a few seconds before trying to connect again.

## Support

Any question related to @performanc/voice or other PerformanC projects can be made in [PerformanC's Discord server](https://discord.gg/uPveNfTuCJ).

## Contribution

It is mandatory to follow the PerformanC's [contribution guidelines](https://github.com/PerformanC/contributing) to contribute to @performanc/voice. Following its Security Policy, Code of Conduct and syntax standard.

## Projects using @performanc/voice

- [NodeLink](https://github.com/PerformanC/NodeLink) - LavaLink alternative written in Node.js.

## License

@performanc/voice is licensed under PerformanC's License, which is a modified version of the MIT License, focusing on the protection of the source code and the rights of the PerformanC team over the source code.

* This project is considered as: [leading standard](https://github.com/PerformanC/contributing?tab=readme-ov-file#project-information).
