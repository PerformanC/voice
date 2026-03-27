# getSpeakStream

## Description

Gets the stream of what an user is saying in the connected voice channel.

## Syntax

```
perfcVoice.getSpeakStream(ssrc, guildId)
```

## Parameters

- `ssrc` - The SSRC of the user.
- `guildId` - The current guildId.

## Return value

If user is found, a `PassThrough` class instance. Otherwise, `null`.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 2.2.4

- Added guildId as the second argument.

### 1.0.0

- Initial implementation

</details>
