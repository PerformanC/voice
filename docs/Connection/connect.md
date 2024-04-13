# connect

## Description

Connects to the Discord voice server and starts the UDP connection.

## Syntax

```
connection.connect(() => {
  console.log('Connected to the voice server!')
})
```

> [!WARNING]  
> An error will be thrown if `voiceStateUpdate` and `voiceServerUpdate` were not called before calling this function.

> [!NOTE]
> When re-connecting after voice channel move, you must call `connection.play()` after calling this function.

## Parameters

- `callback` - A callback that is called when the connection is established.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

### 2.0.3

- `connecting` state will always be emitted after calling this function.

</details>
