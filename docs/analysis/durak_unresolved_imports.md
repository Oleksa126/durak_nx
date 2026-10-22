# Durak NX — Звіт ELF64 / AArch64 Host Oracle (E05 Host Model)

## 1. Підсумок завантаження модулів

- **Кількість модулів:** 4
- **Порядок завантаження:** `libsqlite3.so -> libmain.so -> libunity.so -> libil2cpp.so`
- **Зареєстровано глобальних експортів:** 2805
- **Міжмодульних релокацій розв'язано:** 0
- **Зареєстровано зовнішніх shim-символів (E05.4b):** 79
- **Зовнішніх shim-релокацій розв'язано (relocation sites):** 127
- **Незв'язаних strong (GLOBAL) релокацій (relocation sites):** 631
- **Незв'язаних weak імпортів (дозволено NULL):** 4

## 2. Карта пам'яті модулів (Memory Layout & Alignment)

| Модуль | Allocation Base | Load Bias | Розмір пам'яті | Вирівнювання | PT_LOAD | RELRO | InitArray |
|---|---|---|---|---|:---:|:---:|:---:|
| `libsqlite3.so` | `0x7000000000` | `0x7000000000` | `0x1d0000` | `0x10000` | 2 | Так | 0 |
| `libmain.so` | `0x70001d0000` | `0x70001d0000` | `0x10000` | `0x4000` | 4 | Так | 0 |
| `libunity.so` | `0x70001e0000` | `0x70001e0000` | `0x15cc000` | `0x4000` | 4 | Так | 506 |
| `libil2cpp.so` | `0x70017ac000` | `0x70017ac000` | `0x2000000` | `0x4000` | 4 | Так | 22 |

## 3. Розподіл незв'язаних Strong-імпортів за підсистемами (Ціль для E06 Shims)

| Підсистема | Унікальних символів | Загалом викликів | Приклади символів |
|---|:---:|:---:|---|
| **Bionic/Android SDK (Other)** | 129 | 196 | `__gnu_strerror_r`, `android_set_abort_message`, `asprintf` (+126) |
| **libc (Memory/String)** | 41 | 71 | `bsearch`, `memchr`, `memrchr` (+38) |
| **libc (Pthreads)** | 41 | 83 | `pthread_attr_destroy`, `pthread_attr_getstack`, `pthread_attr_init` (+38) |
| **libc (FS/IO/Stdio)** | 36 | 92 | `__sF`, `access`, `close` (+33) |
| **libc (POSIX/System)** | 34 | 78 | `__FD_ISSET_chk`, `__FD_SET_chk`, `__assert2` (+31) |
| **libandroid (NDK)** | 31 | 31 | `AChoreographer_getInstance`, `AChoreographer_postFrameCallback`, `ALooper_acquire` (+28) |
| **libc (Sockets/Net)** | 22 | 39 | `accept`, `bind`, `connect` (+19) |
| **libEGL** | 20 | 20 | `eglChooseConfig`, `eglCreateContext`, `eglCreatePbufferSurface` (+17) |
| **libdl** | 5 | 18 | `dladdr`, `dlclose`, `dlerror` (+2) |
| **libz** | 3 | 3 | `inflate`, `inflateEnd`, `inflateInit2_` |

## 4. Верифікація безпеки W^X та сегментів

- Усі сегменти завантажуються в режимі RW для накладення релокацій.
- Після релокацій дозволи фіналізуються за заголовками ELF:
  * Код: `RX`
  * Дані: `RW`
  * Rodata / RELRO: `R`
- **Загальний статус W^X:** `PASS (0 порушень)`
- **Порушень правила W^X:** `0` (жодна сторінка не має одночасно прав запису та виконання).
- **Вирівнювання 64 KiB:** успішно застосовано до `libsqlite3.so` без конфліктів у пам'яті.

| Модуль | Всього сторінок | RX сторінок | RW сторінок | RO сторінок | W^X порушень | Статус |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `libsqlite3.so` | 464 | 429 | 4 | 31 | 0 | PASS |
| `libmain.so` | 16 | 1 | 1 | 14 | 0 | PASS |
| `libunity.so` | 5580 | 3915 | 369 | 1296 | 0 | PASS |
| `libil2cpp.so` | 8192 | 4061 | 974 | 3157 | 0 | PASS |
