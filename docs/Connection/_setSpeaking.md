# _setSpeaking

## Description

Sets the speaking state of the bot, this function is meant to be used internally, but can be used if you want to set the speaking state of the bot manually.

## Syntax

```
connection._setSpeaking(1 << 0)
```

> [!WARNING]  
> An error will be thrown if the connection was not initialized. Always check if `connection.ws != null` before calling this function.

## Parameters

- `state` - The [speaking state](https://discord.com/developers/docs/topics/voice-connections#speaking) to set.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

</details>
