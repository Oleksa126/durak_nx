# Штатні звуки: OpenSL ES output gate

Ціль: оригінальний `extracted_durak/libunity.so`, Build-ID `bcc661ea2046416d`.
У логах №19 FMOD реєструє JNI під час runtime і запускає stream thread;
це не доводить наявність звуку. Java output pump вимкнений після підтвердженого
null-source crash; його не ввімкнено цією зміною.

## Відтворювані статичні докази

`python scripts/verify_audio_output.py` (pyelftools, capstone):

- AudioManager шлях `0x834b54` завантажує requested output зі stack slot `0x3c`,
  викликає `0x1082bb8`, який передає його в `0x10293f4`.
- `0x10294d4` читає descriptor `+0x78`, порівнює його з requested output,
  а при збігу створює output через `0x101d414`.
- AudioTrack descriptor builder `0x108e238` записує назву з `0x179510`;
  `0x108e2b4` читає константу з `0x181270` (23), `0x108e334` записує її в `+0x78`.
- OpenSL descriptor builder `0x108f490` записує назву з `0x13292c`;
  `0x108f50c` читає константу з `0x17fae0` (24), `0x108f59c` записує її в `+0x78`.
- Обидва builders зареєстровані через `0x108d7c8` -> `0x101cb54`.
- Platform selection `0x85e0a4` та automatic selection `0x108d874`
  завантажують 23 у `w8`, після чого записують його в requested output.
  Змінено тільки ці два `mov w8,#23` на `mov w8,#24` (`0x52800308`).
- Штатний NOSOUND branch `0x834b04` із type 2 залишається незмінним.
  Не змінюються PlayerPrefs, assets, гучність чи managed AudioSource.

Перед записом перевіряються всі десять слів контексту; mismatch або короткий
image відхиляється без часткового патчу. Патч застосовується до writable staging
та перевіряється після mapping/cache flush у RX. Loader перевіряє цільовий ELF.
Номери й RVA отримані з Durak, а не з донорської гри.

## Runtime перевірка

SDL audio callback уже встановлює власний Bionic TLS перед guest callback.
Успішна послідовність у новому логу:

1. `[AUDIO] OpenSL slCreateEngine called`
2. `[AUDIO] SDL output opened` (48000 Hz, stereo S16)
3. `[AUDIO] OpenSL player` із реальним PCM format
4. `[AUDIO] First nonzero PCM mixed into SDL output` після кліку/гри

Якщо SDL device або player mutex не відкривається, CreateAudioPlayer повертає
реальну помилку замість удаваного успіху. Наявні SDL failure messages збережено.
Перший nonzero PCM логується один раз, без покадрового audio спаму.

Native tests перевіряють null/truncation, mismatch кожного слова, атомарність,
незмінність сусідніх інструкцій і RX corruption. Збірка та ці перевірки успішні;
чути звук на Switch поки **не підтверджено**. Статус: NEEDS_HARDWARE_TEST.

Для тесту замінити лише `durak_nx.nro` -> SD `/switch/durak_nx/durak_nx.nro`.
У грі ввімкнути штатну опцію звуку, перевірити кліки та партію, потім передати лог.

## Hardware log 20: startup crash and memory correction

`durak_nx (20).log` confirms OpenSL engine/player creation and SDL output at
48000 Hz, stereo S16, 1024 samples. No nonzero PCM evidence precedes the crash.
The failing call is `svcMapMemory(dst=0x22000000, size=0x1000000)` with real
result `0xd401`; mprotect propagates failure with errno 14. Pool still has
56180 pages available, so this is not pool exhaustion.

Destination query reports an unmapped extent only up to `0x22830000`.
Atmosphere report `01790947622_05f5d338a7a28000.log` lists eight thread TLS
addresses `0x22830000..0x22830e00`, proving a kernel TLS page inside the attempted
mapping. Software virtmem reservation cannot exclude kernel TLS allocation.
The OC allocator checked for occupied spans at reservation time, but a TLS page
arrived later, before lazy commit. Rescanning cannot relocate a pointer already
returned to Unity, and splitting the mapping cannot overwrite live TLS safely.

Crash PC `0x62ed469b0` minus logged Unity base `0x62dda0000` is RVA `0xfa69b0`:
`str q0,[x25,#-0x10]!`, with x25=`0x23000000`, accessing `0x22fffff0` in the
unbacked range. This explains the Data Abort after the failed commit.

Correction removes stack-window activation from main. Existing mmap requests
use the dedicated aligned heap arena (832 MB in log 20) and existing aligned
newlib fallback. The 384 MB OC pool is no longer allocated. Audio selection,
assets, databases, guest error propagation and executable patches are unchanged.
Physical heap backing trades virtual overcommit capacity for avoidance of the
proven kernel TLS collision. Long-session capacity and audible sound require
the next hardware test; no successful startup is claimed from host tests.
