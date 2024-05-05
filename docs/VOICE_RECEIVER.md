# Discord Voice Receiver

Documentation for implementation of voice receivement for Discord Voice Gateway.

## Table of Contents
- [Voice Receiver](#voice-receiver)
  - [Payload structure](#payload-structure)
  - [Audio Decryption](#audio-decryption)
    - [XSalsa20-Poly1305-Lite](#xsalsa20-poly1305-lite)
    - [XSalsa20-Poly1305](#xsalsa20-poly1305)
    - [XSalsa20-Poly1305-Suffix](#xsalsa20-poly1305-suffix)

## Payload structure

The payload structure of the Discord Voice Gateway is as follows:

| Field           | Type            | Description                        |
| --------------- | --------------- | ---------------------------------- |
| Version & Flags | 8-bit unsigned  | The version of the payload.        |
| Type            | 8-bit unsigned  | The type of the payload.           |
| Sequence        | 16-bit unsigned | The sequence of the payload.       |
| Timestamp       | 32-bit unsigned | The timestamp of the payload.      |
| SSRC            | 32-bit unsigned | The SSRC of the payload.           |
| Audio           | n bytes         | The audio of the payload.          |

> ![NOTE]
> The audio is encrypted with the selected encryption mode.

## Audio Decryption

### XSalsa20-Poly1305-Lite

The audio is encrypted with the XSalsa20-Poly1305-Lite encryption mode. The audio is structured as follows:

| Field           | Type            | Description                        |
| --------------- | --------------- | ---------------------------------- |
| Audio           | n bytes         | The audio of the payload.          |

> ![NOTE]
> The audio is encrypted with `secretKeys`, without a nonce.

### XSalsa20-Poly1305

The audio is encrypted with the XSalsa20-Poly1305 encryption mode. The audio is structured as follows:

| Field           | Type            | Description                        |
| --------------- | --------------- | ---------------------------------- |
| Nonce           | 24 bytes        | The nonce of the audio.            |
| Audio           | n bytes         | The audio of the payload.          |

> ![NOTE]
> The nonce is a cryptographically secure random number.

### XSalsa20-Poly1305-Suffix

The audio is encrypted with the XSalsa20-Poly1305-Suffix encryption mode. The audio is structured as follows:

| Field           | Type            | Description                        |
| --------------- | --------------- | ---------------------------------- |
| Nonce           | 24 bytes        | The nonce of the audio.            |
| Audio           | n bytes         | The audio of the payload.          |

> ![NOTE]
> The nonce sums up 1 for each packet, resetting to 0 after 2 ** 32 packets.
