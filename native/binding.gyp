{
  "targets": [
    {
      "target_name": "voice_send_native",
      "sources": [
        "src/binding.c",
        "src/cthreads.c",
        "src/voice_send.c"
      ],
      "include_dirs": [
        "."
      ],
      "conditions": [
        ["OS=='linux'", {
          "cflags": [
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic"
          ],
          "libraries": [
            "-lsodium",
            "-lpthread"
          ]
        }],
        ["OS=='mac'", {
          "libraries": [
            "-lsodium",
            "-lpthread"
          ],
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
          "defines": [
            "SODIUM_STATIC"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "AdditionalOptions!": [
                "-flto=full",
                "-flto=thin"
              ]
            },
            "VCLibrarianTool": {
              "AdditionalOptions!": [
                "-flto=full",
                "-flto=thin"
              ]
            },
            "VCLinkerTool": {
              "AdditionalOptions!": [
                "-flto=full",
                "-flto=thin",
                "/opt:lldltojobs=<(lto_jobs)"
              ]
            }
          },
          "libraries": [
            "<!(node find-libsodium.js library <(target_arch))",
            "ws2_32.lib"
          ],
          "include_dirs": [
            "src",
            "<!(node find-libsodium.js include <(target_arch))"
          ]
        }]
      ]
    }
  ]
}
