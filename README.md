# @performanc/voice

Performant Discord voice API client for ES6 Node.js

## About

`@performanc/voice` is a JavaScript library for interacting with the Discord voice API. It is designed to be fast, lightweight, and easy to use.

## Installation

```sh
npm install @performanc/voice
```

## Usage

```js
import perfcVoice from '@performanc/voice'

...

const guildId = '123123123'
const userId = '123123123'

const connection =  perfcVoice.joinVoiceChannel({ guildId: guildId, userId: userId })

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

connection.on('stateChange', (oldState, newState) => {
  if (newState.status == 'ready') {
    console.log('Voice connection ready')
  }
})

connection.on('playerStateChange', (oldState, newState) => {
  if (newState.status == 'idle' && oldState.status != 'idle') {
    console.log('End of audio')
  }

  if (newState.status == 'playing' && oldState.status != 'playing') {
    console.log('Playing audio')
  }
})

connection.connect(() => {
  connection.play(stream)
})
```

> [!WARNING]  
> `@performanc/voice` does not transcode audio, it must be already a valid Opus stream. If you wish to play an arbitrary audio file, see [ffmpeg](https://ffmpeg.org/) and [prism-media](https://npmjs.com/package/prism-media), or our [NodeLink code](https://github.com/PerformanC/NodeLink/tree/main/src/voice/utils.js).

## Documentation

Documentation can be found [here](docs/).

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting a pull request.

## License

`@performanc/voice` is licensed under PerformanC's License, which is a modified version of the MIT License, focusing on the protection of the source code and the rights of the PerformanC team over the source code.

If you wish to use some part of the source code, you must contact us first, and if we agree, you can use the source code, but you must give us credit for the source code you use.
