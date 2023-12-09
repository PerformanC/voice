# voiceStateUpdate 

## Description

Adds informations to create a connection to a voice channel.

## Syntax

```
connection.voiceServerUpdate({
  token: '...',
  endpoint: '...'
})
```

> [!WARNING]  
> Invalid parameters will NOT cause the function to throw an error, but will instead cause the connection to emit a 4006 error from Discord.

## Parameters

- `options` - An object containing the following parameters:
  - `token` - The token of the voice channel.
  - `endpoint` - The endpoint of the voice channel.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

</details>
