#ifndef OS_COMPAT_H
#define OS_COMPAT_H

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN

  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mswsock.h>

#else
  #include <time.h>

  #include <arpa/inet.h>
#endif

#ifdef _WIN32
  typedef SOCKET os_socket_t;
  #define OS_INVALID_SOCKET INVALID_SOCKET
#else
  typedef int os_socket_t;
  #define OS_INVALID_SOCKET (-1)
#endif

static inline int os_sendto(os_socket_t fd, const void *buf, size_t len, int flags, const void *addr, size_t addr_len) {
  #ifdef _WIN32
    int sent = sendto(fd, (const char *)buf, (int)len, flags, (const struct sockaddr *)addr, (int)addr_len);
    return sent == SOCKET_ERROR ? -1 : sent;
  #else
    return (int)sendto(fd, buf, len, flags, (const struct sockaddr *)addr, (socklen_t)addr_len);
  #endif
}

static inline int os_inet_pton(const char *src, void *dst) {
  #ifdef _WIN32
    return InetPtonA(AF_INET, src, dst);
  #else
    return inet_pton(AF_INET, src, dst);
  #endif
}

static inline long long os_now_ns(void) {
  #ifdef _WIN32
    static LARGE_INTEGER freq;
    static int freq_initialized = 0;

    if (!freq_initialized) {
      QueryPerformanceFrequency(&freq);
      freq_initialized = 1;
    }

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    return (now.QuadPart * 1000000000LL) / freq.QuadPart;
  #else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  #endif
}

static inline void os_sleep_ns(long long ns) {
  #ifdef _WIN32
    if (ns > 0) {
      DWORD ms = (DWORD)(ns / 1000000LL);
      if (ms == 0) ms = 1;

      Sleep(ms);
    }
  #else
    if (ns > 0) {
      struct timespec ts = {
        .tv_sec = (time_t)(ns / 1000000000LL),
        .tv_nsec = (long)(ns % 1000000000LL)
      };

      nanosleep(&ts, NULL);
    }
  #endif
}

#endif /* OS_COMPAT_H */
