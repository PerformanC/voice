# Connection constructor

## Description

The constructor for the `Connection` class.

## Parameters

- `options` - An object containing the following parameters:
  - `guildId` - The ID of the guild that the voice channel is in.
  - `userId` - The ID of the user that is connecting to the voice channel.

## Return value

A `Connection` class instance, with the following properties:

- `guildId` - The ID of the guild that the voice channel is in.
- `userId` - The ID of the user that is connecting to the voice channel.
- `encryption` - The encryption mode of the UDP connection. Can be one of the following:
  - `xsalsa20_poly1305` - Normal encryption.
  - `xsalsa20_poly1305_suffix` - Normal encryption with a suffix.
  - `xsalsa20_poly1305_lite` - Lite encryption. **Recommended for best performance.**

- `ws` - The WebSocket connection to the Discord voice server. `null` if not connected.

- `state` - An object containing the following properties:
  - `status` - The status of the connection. Can be one of the following:
    - `disconnected` - The connection is not connected to the Discord voice server.
    - `connecting` - The connection is connecting to the Discord voice server.
    - `connected` - The connection is connected to the Discord voice server.
    - `reconnecting` - The connection is reconnecting to the Discord voice server.
    - `disconnecting` - The connection is disconnecting from the Discord voice server.

- `playerState` - An object containing the following properties:
  - `status` - The status of the audio stream. Can be one of the following:
    - `idle` - The audio stream is not playing.
    - `playing` - The audio stream is playing.
    - `paused` - The audio stream is paused.

- `sessionId` - The session ID of the connection. `null` if not connected.

- `voiceServer` - The voice server information of the connection. `null` if not connected.
  - `token` - The token of the voice server.
  - `endpoint` - The endpoint of the voice server.

- `hbInterval` - The interval that sends a heartbeat packet to the Discord voice server. `null` if not connected.

- `udpInfo` - The UDP information of the connection. `null` if not connected.
  - `ip` - The IP address of the Discord voice server.
  - `port` - The port of the Discord voice server.
  - `mode` - The mode of the UDP connection. Can be one of the following:
    - `xsalsa20_poly1305_lite` - The UDP connection is encrypted. This is the default mode. Can be changed by modifying code of the library. **Do NOT change unless you know what you're doing.**

- `udp` - The UDP connection to the Discord voice server. `null` if not connected.

- `ping` - The ping of the connection. `-1` if not connected.

- `statistics` - An object containing the following properties:
  - `packetsSent` - The number of packets sent to the Discord voice server.
  - `packetsLost` - The number of packets lost.
  - `packetsExpected` - The number of packets expected.

- `player` - An object containing the following properties:
  - `sequence` - The sequence of the audio stream.
  - `timestamp` - The timestamp of the audio stream.

- `nonce` - The nonce of the connection.

- `nonceBuffer` - The nonce buffer of the connection.

- `playInterval` - The `20ms` interval that sends an audio packet to the Discord voice server. `null` if not connected.

- `audioStream` - The audio stream of the connection. `null` if not connected.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

### 1.0.4

- Added `encryption` property and parameter
- Added `statistics` property

</details>
