let libraries = {
  'sodium-native': (sodium) => ({
    open: (buffer, nonce, key) => {
      const output = Buffer.allocUnsafe(buffer.length - sodium.crypto_secretbox_MACBYTES)
      sodium.crypto_secretbox_open_easy(output, buffer, nonce, key)
  
      return output
    },
    close: (buffer, nonce, key) => {
      const output = Buffer.allocUnsafe(buffer.length + sodium.crypto_secretbox_MACBYTES)
      sodium.crypto_secretbox_easy(output, buffer, nonce, key)
  
      return output
    },
    random: (number) => {
      const output = Buffer.allocUnsafe(number)
      sodium.randombytes_buf(output)
  
      return output 
    }
  }),
  'libsodium-wrappers': (sodium) => ({
    open: sodium.crypto_secretbox_open_easy,
    close: sodium.crypto_secretbox_easy,
    random: sodium.randombytes_buf
  }),
  'tweetnacl': (sodium) => ({
    open: sodium.secretbox.open,
    close: sodium.secretbox,
    random: sodium.randombytes_buf
  })
}

libraries = {
  ...libraries,
  'sodium-javascript': libraries['sodium-native'],
}

const functions = {
  open: null,
  close: null,
  random: null
}

void (async () => {
  let index = 0
  Object.keys(libraries).forEach(async (name) => {
    try {
      const lib = await import(name)

      if (functions.open) return;

      if (name == 'libsodium-wrappers') await lib.default.ready

      functions.open = libraries[name](lib.default).open
      functions.close = libraries[name](lib.default).close
      functions.random = libraries[name](lib.default).random
    } catch {}

    if (index == libraries.length - 1 && !functions.open) {
      throw new Error('Could not load any sodium library')
    }

    index++
  })
})()

export default functions
