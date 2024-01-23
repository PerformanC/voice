# joinVoiceChannel 

## Description

Creates informations to create a connection to a voice channel.

## Syntax

```
perfcVoice.joinVoiceChannel({
  guildId: '12345678910',
  userId: '12345678910'
})
```

> [!WARNING]  
> Invalid parameters will NOT cause the function to throw an error, but will instead cause the connection to fail silently.

## Parameters

- `options` - An object containing the following parameters:
  - `guildId` - The ID of the guild that the voice channel is in.
  - `userId` - The ID of the user that is connecting to the voice channel.
  - `encryption` - The encryption mode of the UDP connection. Can be one of the following:
    - `xsalsa20_poly1305` - Normal encryption.
    - `xsalsa20_poly1305_suffix` - Normal encryption with a suffix.
    - `xsalsa20_poly1305_lite` - Lite encryption. **Recommended for best performance.**

## Return value

A `Connection` class instance.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

### 1.0.4

- Added necessary `encryption` parameter

</details>
