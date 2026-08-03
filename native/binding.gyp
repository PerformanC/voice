{
  "targets": [
    {
      "target_name": "voice_send_native",
      "sources": [
        "src/binding.c",
        "src/voice_send.c",
        "src/cthreads.c"
      ],
      "include_dirs": [
        "."
      ],
      "libraries": [
        "-lsodium",
        "-lpthread"
      ],
      "conditions": [
        ["OS=='linux'", {
          "cflags": [
            "-std=c99",
            "-D_POSIX_C_SOURCE=200809L",
            "-Wall",
            "-Wextra",
            "-Wpedantic"
          ],
          "ldflags": []
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "OTHER_CFLAGS": [
              "-std=c99",
              "-Wall",
              "-Wextra",
              "-Wpedantic",
            ]
          }
        }],
        ["OS=='win'", {
          "libraries": [
            "-lsodium.lib"
          ],
          "include_dirs": [
            "src"
          ]
        }]
      ]
    }
  ]
}
