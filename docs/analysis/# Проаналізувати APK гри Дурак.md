# Проаналізувати APK гри Дурак

> Durak\_25.0.apks --&#x20;
>
> Я хочу зрозуміти, чи реально запустити Android-гру «Дурак»
> (package: ru.appscraft.durak) на прошитому Nintendo Switch OLED без встановлення Android.
>
> Твоє завдання — ТІЛЬКИ проаналізувати APK і оцінити технічну можливість такого запуску.
>
> Потрібно визначити:
>
> - на чому написана гра: Java/Kotlin, Unity, Cocos, native C/C++ або інше;
> - які архітектури є в APK, особливо чи є arm64-v8a;
> - які native .so бібліотеки є всередині;
> - де знаходиться основна логіка гри: у classes.dex чи native ARM64 бібліотеках;
> - які Android API та зовнішні SDK використовуються;
> - чи можна теоретично зробити wrapper/compatibility layer для запуску під Atmosphère / Horizon OS без Android;
> - чи є вже схожі open-source проєкти для Nintendo Switch, які могли б бути основою.
>
> Нічого поки не реалізовуй і не пиши wrapper.
>
> Наприкінці дай короткий висновок:
>
> 1. Наскільки реально це зробити.
> 2. Який підхід виглядає найбільш перспективним.
> 3. Які головні технічні проблеми будуть.
> 4. Чи варто взагалі братися за wrapper саме для цього APK.
>
> Не роби припущень — спочатку досліди фактичний вміст APK.

<details><summary>6 previous messages</summary>

> Спочатку знайду й розпакую `Durak_25.0.apks`, визначу структуру split APK, ABI, DEX/native-бібліотеки та маніфести. Потім окремо звірю потенційні open-source основи для Switch за первинними джерелами; жодних файлів гри змінювати не буду.
>
> <details><summary>Ran 3 commands</summary>
>
> - Ran `pwd && rg --files -g 'Durak_25.0.apks' -g '*.apks' -g '*.apk' -g 'AGENTS.md' -g '!**/.git/**' | sed -n '1,120p'`
> - Ran `file Durak_25.0.apks && unzip -l Durak_25.0.apks | sed -n '1,240p' && command -v jadx || true && command -v apktool || true && command -v aapt2 || command -v aapt || true && command -v baksmali || true`
> - Ran `work=$(mktemp -d /tmp/durak-analysis.XXXXXX); unzip -q Durak_25.0.apks -d "$work"; echo "$work"; for apk in "$work"/*.apk; do echo "APK $(basename "$apk")"; unzip -l "$apk" | sed -n '1,220p'; done`
>
> </details>
>
> Архів уже дає важливу фактичну відповідь: це Android App Bundle із `base.apk` та окремим `arm64-v8a` split. Усередині є Unity/IL2CPP (`libunity.so`, `libil2cpp.so`, `global-metadata.dat`), тож зараз перевіряю, яка частина логіки справді скомпільована в IL2CPP, а що лишилося в DEX як Android-обв’язка та рекламні SDK.
>
> <details><summary>Ran 13 commands</summary>
>
> - Ran `work=/tmp/durak-analysis.FeTqD3; mkdir -p "$work/base" "$work/arm64"; unzip -q "$work/base.apk" -d "$work/base"; unzip -q "$work/split_config.arm64_v8a.apk" -d "$work/arm64"; echo 'ScriptingAssemblies.json'; sed -n '1,240p' "$work/base/assets/bin/Data/ScriptingAssemblies.json"; echo 'boot.config'; sed -n '1,160p' "$work/base/assets/bin/Data/boot.config"; echo 'Unity fingerprint'; unzip -p "$work/base.apk" META-INF/com.android.games.engine.build_fingerprint; echo; echo 'ELF tools'; command -v readelf || true; command -v llvm-readelf || true; command -v nm || true; command -v objdump || true; echo 'Python modules'; python3 - <<'PY'
> mods=['androguard','apkutils','lief','elftools']
> for m in mods:
>  try:
>   x=__import__(m); print(m, getattr(x,'__version__','installed'))
>  except Exception as e: print(m, 'NO')
> PY
> file "$work"/arm64/lib/arm64-v8a/*.so`
> - Ran `for d in /opt/homebrew/bin /usr/local/bin "$HOME/Library/Android/sdk" "$HOME/.local/bin"; do if [ -d "$d" ]; then find "$d" -maxdepth 5 \( -name aapt -o -name aapt2 -o -name apkanalyzer -o -name jadx -o -name apktool -o -name bundletool.jar \) -print 2>/dev/null; fi; done; find "$HOME/.gradle" "$HOME/.m2" -maxdepth 7 \( -iname '*bundletool*.jar' -o -iname '*apkanalyzer*.jar' \) -print 2>/dev/null | sed -n '1,40p'`
> - Ran `python3 -m pip install --target /tmp/durak-pytools androguard`
> - Ran `ls -la /tmp/durak-pytools 2>/dev/null || true; command -v python3; python3 --version 2>&1 || true; command -v python || true; command -v java || true; java -version 2>&1 | sed -n '1,8p'`
> - Ran `/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 -m pip install --target /tmp/durak-pytools androguard`
> - Ran `/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 -m pip install --target /tmp/durak-pytools androguard`
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from androguard.core.apk import APK
> from loguru import logger
> logger.remove()
> p='/tmp/durak-analysis.FeTqD3/base.apk'
> a=APK(p)
> print('package',a.get_package())
> print('versionName',a.get_androidversion_name(),'versionCode',a.get_androidversion_code())
> print('minSdk',a.get_min_sdk_version(),'targetSdk',a.get_target_sdk_version(),'maxSdk',a.get_max_sdk_version())
> print('effective target',a.get_effective_target_sdk_version())
> print('main activity',a.get_main_activity())
> print('activities',len(a.get_activities()))
> for x in a.get_activities(): print(' A',x)
> print('services',len(a.get_services()))
> for x in a.get_services(): print(' S',x)
> print('receivers',len(a.get_receivers()))
> for x in a.get_receivers(): print(' R',x)
> print('providers',len(a.get_providers()))
> for x in a.get_providers(): print(' P',x)
> print('permissions',len(a.get_permissions()))
> for x in a.get_permissions(): print(' PERM',x)
> print('features')
> for x in a.get_features(): print(' FEAT',x)
> print('libraries')
> for x in a.get_libraries(): print(' LIB',x)
> xml=a.get_android_manifest_xml()
> print('---MANIFEST---')
> print(__import__('lxml').etree.tostring(xml, pretty_print=True, encoding='unicode'))
> PY`
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from androguard.core.apk import APK
> from androguard.core.dex import DEX
> from collections import Counter
> from loguru import logger
> logger.remove()
> a=APK('/tmp/durak-analysis.FeTqD3/base.apk')
> allc=[]
> for i,d in enumerate(a.get_all_dex(),1):
>  vm=DEX(d)
>  names=[c.get_name().strip('L;').replace('/','.') for c in vm.get_classes()]
>  allc+=names
>  print('dex',i,'classes',len(names),'methods',sum(len(c.get_methods()) for c in vm.get_classes()))
> print('total classes',len(allc))
> for depth in [2,3,4]:
>  c=Counter('.'.join(x.split('.')[:depth]) for x in allc)
>  print('\nTOP depth',depth)
>  for k,v in c.most_common(60): print(v,k)
> print('\nAppscraft / Unity player / plugin candidates')
> for x in allc:
>  if any(s in x.lower() for s in ['appscraft','unity3d.player','appodealstack','simpleandroidnotifications']): print(x)
> PY`
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> try:
>  import elftools; print('elftools yes')
> except Exception as e: print('no',e)
> PY
> strings -a /tmp/durak-analysis.FeTqD3/arm64/lib/arm64-v8a/libil2cpp.so | rg -o 'lib[^ /]+\.so' | sort -u
> strings -a /tmp/durak-analysis.FeTqD3/arm64/lib/arm64-v8a/libunity.so | rg -o 'lib[^ /]+\.so' | sort -u`
> - Ran `/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 -m pip install --target /tmp/durak-pytools pyelftools`
> - Ran `/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 -m pip install --target /tmp/durak-pytools pyelftools`
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> root=Path('/tmp/durak-analysis.FeTqD3/arm64/lib/arm64-v8a')
> for p in sorted(root.glob('*.so')):
>  with p.open('rb') as f:
>   e=ELFFile(f); dyn=e.get_section_by_name('.dynamic')
>   needed=[x.needed for x in dyn.iter_tags() if x.entry.d_tag=='DT_NEEDED'] if dyn else []
>   sym=e.get_section_by_name('.dynsym')
>   ex=[]; un=[]
>   if sym:
>    for s in sym.iter_symbols():
>     if not s.name: continue
>     if s['st_shndx']=='SHN_UNDEF': un.append(s.name)
>     elif s['st_info']['bind'] in ('STB_GLOBAL','STB_WEAK'): ex.append(s.name)
>   print(f'{p.name} size={p.stat().st_size} needed={needed}')
>   jniex=[x for x in ex if x.startswith('JNI') or x.startswith('Java_') or 'il2cpp' in x.lower()]
>   print(' exports',len(ex),'jni/il2cpp sample',jniex[:30])
>   api=[x for x in un if x.startswith(('AAsset','ANative','ALooper','AInput','AHardware','AMotion','AChoreo','ASensor','egl','gl','vk','JNI_'))]
>   print(' android/graphics imports sample',api[:40])
> PY`
> - Ran `find /tmp/durak-analysis.FeTqD3/base -type f \( -name '*.properties' -o -name '*.version' \) -maxdepth 8 -print | sort | while IFS= read -r f; do printf '%s: ' "${f#/tmp/durak-analysis.FeTqD3/base/}"; tr '\n' ' ' < "$f"; printf '\n'; done`
>
> </details>
>
> Картина вже чітка: власних Java/Kotlin-класів гри в DEX фактично немає — для `ru.appscraft.durak` знайдено лише згенеровані `R`-класи. `Assembly-CSharp.dll` перелічено серед IL2CPP assemblies, а сама ігрова C#-логіка зведена в ARM64 `libil2cpp.so` разом із `global-metadata.dat`. Тепер перевіряю сумісність Android ELF/JNI-графіки з Horizon і чи існує готова база, яка справді працює в потрібному напрямку.
>
> <details><summary>Ran 3 commands, searched the web</summary>
>
> Searched the web for `site:github.com switchbrew libnx Nintendo Switch homebrew Horizon OS ...`
>
> Searched the web for `site:github.com/Viridite/VNX-Translation-Core Unity IL2CPP libunity Android Horizon Switch ...`
>
> Searched the web for `https://raw.githubusercontent.com/Viridite/VNX-Translation-Core/main/.gitmodules`
>
> Searched the web for `https://github.com/Viridite/VNX-Unity-Runtime`
>
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> import re,struct,hashlib
> from pathlib import Path
> m=Path('/tmp/durak-analysis.FeTqD3/base/assets/bin/Data/Managed/Metadata/global-metadata.dat').read_bytes()
> print('metadata bytes',len(m),'magic/version',hex(struct.unpack_from('<I',m)[0]),struct.unpack_from('<I',m,4)[0])
> ss=[x.decode('utf-8','ignore') for x in re.findall(rb'[ -~]{4,}',m)]
> for pat in ['Durak','Card','Deck','Bot','Player','GameController','Appscraft','Assembly-CSharp','SimpleSQL','Appodeal']:
>  vals=[]
>  for i,s in enumerate(ss):
>   if pat.lower() in s.lower(): vals.append(s)
>  print('\n',pat, vals[:50])
> print('\nSHA256')
> for p in [Path('/Users/oleksandrbazavliak/Documents/Durak Mod/Durak_25.0.apks'),Path('/tmp/durak-analysis.FeTqD3/base.apk'),Path('/tmp/durak-analysis.FeTqD3/split_config.arm64_v8a.apk')]:
>  h=hashlib.sha256(p.read_bytes()).hexdigest(); print(p.name,p.stat().st_size,h)
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> b=Path('/tmp/durak-analysis.FeTqD3/base/assets/bin/Data/Managed/Metadata/global-metadata.dat').read_bytes()
> vals=[]
> for x in b.split(b'\0'):
>  if 4<=len(x)<=220:
>   try:s=x.decode('utf-8')
>   except:continue
>   if s.startswith(('android.','android/','com.','com/','io.','java.','javax.','org.')) and all(ord(c)>=32 for c in s): vals.append(s)
> for s in sorted(set(vals)): print(s)
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> import re
> from pathlib import Path
> b=Path('/tmp/durak-analysis.FeTqD3/base/assets/bin/Data/Managed/Metadata/global-metadata.dat').read_bytes()
> pat=rb'(?<![A-Za-z0-9_])(?:android|com|io|java|javax|org)(?:[./][A-Za-z_$][A-Za-z0-9_$]*){1,12}'
> for x in sorted(set(m.decode() for m in re.findall(pat,b))):
>  if len(x)<200: print(x)
> PY`
>
> Searched the web for `site:github.com/NaGaa95 Nintendo Switch Android Unity port libunity libil2cpp ...`
>
> </details>
</details>

## Результат аналізу

Проаналізовано саме файл `Durak_25.0.apks`:

- package: `ru.appscraft.durak`
- version: `25.0`, versionCode `250`
- SHA-256: `91e51b321ae26382a273534225165f229f41c13831e9d16b164de3679a74a615`
- склад архіву:
  - `base.apk`
  - `split_config.arm64_v8a.apk`

### На чому написана гра

Це **Unity 6 + C# → IL2CPP**, а не звичайна Java/Kotlin-гра.

Точний build fingerprint:

```text
Unity 6000.4.0b6
IL2CPP
Release
StripEngineCode:1
```

У `ScriptingAssemblies.json` присутні:

- `Assembly-CSharp.dll`
- `Assembly-CSharp-firstpass.dll`
- `UnityEngine.*`
- `UnityEngine.UI.dll`
- `Unity.TextMeshPro.dll`
- `spine-unity.dll`
- `SimpleSQL_Runtime.dll`
- `Newtonsoft.Json.dll`
- `AppodealStack.*`
- `Unity.Purchasing.*`
- `Unity.Services.Analytics.*`

Отже, ігровий код спочатку був C#, але вже AOT-компільований у native ARM64 через IL2CPP.

## Архітектури

У наданому `.apks` є лише:

```text
arm64-v8a
```

`armeabi-v7a`, `x86` та `x86_64` відсутні.

Це позитивний фактор: Nintendo Switch OLED також використовує ARMv8-A/AArch64. Емуляція набору команд не потрібна. Однак Android ARM64 ELF не є бінарно сумісним із Horizon — потрібні власний ELF loader та Android/Bionic/JNI shim.

## Native-бібліотеки

| Бібліотека | Розмір | Призначення |
|---|---:|---|
| `libil2cpp.so` | 31,256,704 | IL2CPP runtime і скомпільований C#-код гри |
| `libunity.so` | 21,388,304 | Unity Player: графіка, життєвий цикл, input, audio |
| `libsqlite3.so` | 1,797,248 | Локальна база даних |
| `libsigner.so` | 1,131,240 | Adjust signature/attribution |
| `libapplovin-native-crash-reporter.so` | 860,200 | AppLovin crash reporter |
| `libsentry.so` | 720,048 | Sentry native crash reporting |
| `libsentry-android.so` | 16,832 | JNI-обв’язка Sentry |
| `libdatastore_shared_counter.so` | 7,112 | AndroidX DataStore |
| `libmain.so` | 6,696 | Unity Android bootstrap/entry point |

`libunity.so` безпосередньо залежить від Android-компонентів:

```text
libmain.so
libandroid.so
liblog.so
libz.so
libEGL.so
libmediandk.so
libm.so
libdl.so
libc.so
```

Серед імпортів виявлені:

- `ANativeWindow_*`
- `AChoreographer_*`
- `ALooper_*`
- `ASensorManager_*`
- EGL surface/context API
- Android Media NDK

Саме ці API потрібно відтворювати поверх libnx, switch-mesa/SDL та сервісів Horizon.

## Де знаходиться логіка гри

Основна логіка знаходиться **не в `classes.dex`, а в `libil2cpp.so` + `global-metadata.dat`**.

Докази:

- `global-metadata.dat`: 7,639,464 байти, metadata version `39`;
- присутній `Assembly-CSharp.dll` у списку IL2CPP assemblies;
- у metadata видно власні ігрові назви й рядки: `GenerateDeck`, `PlaceCardOnTableToBeat`, `transfer_card`, `shuffle_cards`, AI-методи вибору карт, типи режимів «підкидний/перевідний» тощо;
- у восьми DEX-файлах загалом приблизно 65,468 класів, але `ru.appscraft.durak` містить лише згенеровані `R`, `R$string`, `R$drawable`, `R$mipmap`;
- власних Java/Kotlin-класів із правилами гри там немає.

DEX — це переважно:

- `UnityPlayerActivity` і Java-частина Unity;
- рекламні SDK;
- billing, analytics, attribution;
- AndroidX і системна Android-обв’язка.

`libmain.so` є точкою запуску, `libunity.so` — рушієм, а фактична C#-логіка гри виконується з `libil2cpp.so`.

## Android API та SDK

Маніфест:

- minSdk: `25`
- targetSdk/compileSdk: `35`
- main activity: `com.unity3d.player.UnityPlayerActivity`
- обов’язковий OpenGL ES: `3.0`
- Vulkan оголошено як необов’язковий
- 65 Activity, 12 Service, 17 Receiver, 13 Provider

Основні Android-можливості:

- мережа та Wi-Fi;
- зовнішнє сховище;
- wake lock;
- вібрація;
- notifications;
- foreground services;
- Google Play Billing і license check;
- Advertising ID та AdServices;
- WebView/Custom Tabs.

Виявлені зовнішні SDK:

- Appodeal;
- AppLovin/MAX;
- BidMachine і Bidon;
- Google Mobile Ads / Ad Manager;
- Unity Ads;
- Vungle;
- Yandex Mobile Ads;
- Mintegral/MBridge;
- Bigo Ads;
- Fyber;
- AppMetrica;
- Firebase Analytics, Remote Config, Installations;
- AppsFlyer;
- Adjust;
- Sentry;
- Google Play Billing `8.0.0`;
- Play Integrity і Play Core;
- Unity IAP;
- Unity Analytics;
- Unity Android Notifications / Hippogames notifications;
- AndroidX WorkManager, Room, DataStore;
- OkHttp, protobuf, Kotlin coroutines.

Для базової офлайн-гри більшість рекламних і аналітичних SDK можна потенційно заглушити. Для повної функціональності — реклама, покупки, мережеві турніри, акаунт і серверні режими — їх доведеться або реалізувати, або акуратно обходити на рівні JNI/IL2CPP.

## Чи можливий wrapper під Atmosphère/Horizon

Теоретично — **так**. Практично це буде не простий wrapper APK, а per-title native port/compatibility layer:

```text
NRO
 ├─ Android ARM64 ELF loader
 ├─ Bionic/libc/libdl/liblog shims
 ├─ fake JavaVM + JNI
 ├─ UnityPlayer lifecycle
 ├─ ANativeWindow/Surface/Choreographer
 ├─ EGL/GLES3 → switch-mesa
 ├─ audio/input/touch/storage/network
 └─ stubs для Appodeal, Billing, Analytics тощо
        ↓
 libmain.so → libunity.so → libil2cpp.so
```

Наявність ARM64 — необхідна умова, але далеко не достатня. Бінарники очікують Bionic, Android linker semantics, Java VM, Activity/Surface lifecycle та Android NDK.

## Схожі проєкти

Найрелевантніша основа — [`laytonbmr_nx`](https://github.com/NaGaa95/laytonbmr_nx). Це MIT-проєкт, який завантажує Android `libmain.so`, `libunity.so` та `libil2cpp.so` під Horizon. Особливо важливо, що його ціль — **Unity 6000.0.58f2**, тобто та сама генерація Unity 6, що й у Durak 6000.4.0b6.

Також корисні:

- [`angrybirdsjourney_nx`](https://github.com/NaGaa95/angrybirdsjourney_nx) — Android ARM64 Unity 2022.3 IL2CPP wrapper, MIT;
- [`baldi_nx`](https://github.com/ChanseyIsTheBest/baldi_nx) — Unity/IL2CPP loader із fake JNI, OpenSL ES та input hooks;
- [`HCR_NX`](https://github.com/xflipperkast/HCR_NX) — title-specific Android compatibility layer з ELF/JNI/GLES/audio/input, але для cocos2d-x;
- [`Viridite/VNX-Translation-Core`](https://github.com/Viridite/VNX-Translation-Core) — загальний ARM64 ELF/JNI/Bionic loader. Його cocos2d-x шлях уже запускав Hill Climb Racing, але Unity-модуль поки дуже ранній;
- [`VNX-Unity-Runtime`](https://github.com/Viridite/VNX-Unity-Runtime) — окремий Unity runtime. Автори прямо зазначають, що він поки лише завантажує бібліотеки та виконує `JNI_OnLoad`; жодна Unity-гра через нього ще не працює;
- [`libnx`, `nx-hbloader`, switch-examples](https://github.com/switchbrew) — базова інфраструктура Horizon homebrew.

Viridite називає себе source-available, але його non-commercial ліцензія не є класичною OSI open-source ліцензією. Для чистої MIT-бази кращі per-title порти NaGaa95.

Switchroot Android технічно вирішує проблему, але це окрема Android OS, тому не відповідає умові запуску під Horizon без Android.

## Короткий висновок

1. **Наскільки реально:** запуск офлайн-ядра гри технічно реальний, орієнтовно **6/10**. Повна Android-функціональність із рекламою, IAP, analytics та online — приблизно **2/10**.

2. **Найперспективніший підхід:** per-title wrapper на основі `laytonbmr_nx` або споріднених Unity/IL2CPP портів. Завантажувати оригінальні ARM64 `libmain/libunity/libil2cpp`, а не переносити чи декомпілювати логіку гри.

3. **Головні проблеми:** Unity 6000.4 lifecycle/JNI, Android Surface і Choreographer, Bionic ABI, GLES3, input/audio/storage, JNI-виклики з IL2CPP та велика кількість рекламних/Google SDK. Імовірно знадобляться version-specific patches для конкретних `.so`.

4. **Чи варто братися:** так, якщо мета — дослідницький per-title порт із базовою офлайн-грою. Ні, якщо потрібен швидкий універсальний APK wrapper або повна відповідність Android-версії. Цей APK складніший за хороший перший тест через Unity 6 і дуже важкий SDK-стек, але наявність близького Unity 6 проєкту `laytonbmr_nx` робить задачу вже не суто теоретичною.

> реклами, анаілти і т не потрібно. тільки офлан гра

Це суттєво підвищує реалістичність.

Якщо потрібна лише офлайн-гра, можна повністю заглушити або обійти:

- рекламу й Appodeal/медіаційні SDK;
- Firebase, AppMetrica, AppsFlyer, Adjust і Sentry;
- Google Play Billing, ліцензування та покупки;
- Unity Analytics;
- push-сповіщення;
- мережеві турніри, чат, рейтинги й синхронізацію.

Залишається основний контур:

```text
libmain.so → libunity.so → libil2cpp.so
                    ↓
         локальні Unity assets і SQLite
```

Потрібно забезпечити лише:

- завантаження Android ARM64 ELF;
- Bionic/libc/libdl compatibility layer;
- мінімальний fake JavaVM/JNI для `UnityPlayer`;
- EGL/OpenGL ES 3 через switch-mesa;
- Surface/Choreographer та Unity render loop;
- touchscreen і, бажано, Joy-Con mapping;
- аудіо;
- локальне файлове сховище, PlayerPrefs і `libsqlite3.so`;
- нейтральні відповіді для SDK: «реклама недоступна», «покупок немає», «offline», без зависання гри.

Для цього сценарію я б оцінив шанс отримати працездатну офлайн-гру як **7/10**, але складність усе одно висока через Unity 6000.4. Найкраща відправна точка — [`laytonbmr_nx`](https://github.com/NaGaa95/laytonbmr_nx), бо він уже орієнтований на Android Unity 6000/IL2CPP під Horizon. `Viridite` зараз менш практичний саме для Unity: його Unity runtime ще не запускає повноцінні ігри.

Головний ризик — не реклама, а запуск конкретної версії `libunity.so`, правильний JNI lifecycle та збереження. Якщо гра дозволяє дійти до локального матчу без обов’язкової серверної ініціалізації, **wrapper саме для цього APK уже має практичний сенс**. Повноцінний Android compatibility layer не потрібен; краще робити вузький per-title wrapper тільки для офлайн-режиму.

> а чи можливий реверс інженіринг?

Так, для цього APK реверс-інжиніринг цілком можливий. Причому набір файлів сприятливий: є незашифровані `libil2cpp.so` і `global-metadata.dat` версії 39.

Що реально відновити:

- класи, структури, поля й назви методів з `Assembly-CSharp`;
- значну частину логіки правил, ботів і станів гри;
- виклики Unity API;
- JNI-виклики до Android, реклами, покупок та аналітики;
- формати локальних збережень і структуру SQLite;
- сцени, текстури, звуки, префаби та інші Unity assets;
- native call graph і точки входу в `libunity.so`/`libil2cpp.so`.

Типовий ланцюжок аналізу:

```text
global-metadata.dat + libil2cpp.so
            ↓
   IL2CPP metadata dumper
            ↓
типи, методи, адреси, псевдо-assemblies
            ↓
 Ghidra / IDA / Binary Ninja
            ↓
відновлення поведінки потрібних функцій
```

Інструменти:

- Cpp2IL або Il2CppDumper/il2cpp-dumper-rs — відновлення IL2CPP metadata;
- Ghidra чи IDA — ARM64-декомпіляція;
- AssetRipper — перегляд Unity assets;
- JADX/Androguard — DEX і Android-обв’язка;
- Frida/профайлер на Android-пристрої — динамічне трасування, якщо знадобиться.

Важливе обмеження: це не поверне оригінальний Unity-проєкт і точний C#-код. IL2CPP уже перетворив C# на оптимізований C++, а потім на ARM64. Результатом будуть приблизні псевдокод, типи, адреси функцій і реконструйована поведінка.

Для wrapper не потрібно реверсити всю гру. Раціонально дослідити лише:

1. Послідовність запуску `libmain → libunity → libil2cpp`.
2. Зареєстровані через JNI методи UnityPlayer.
3. AndroidJavaClass/AndroidJavaObject виклики з `Assembly-CSharp`.
4. Перевірки реклами, IAP, ліцензії та мережі.
5. Ініціалізацію локального матчу.
6. Input, audio, PlayerPrefs і SQLite.
7. Місця, де відсутній Android SDK може спричинити зависання або crash.

Найперспективніший варіант — **не переписувати гру за результатами реверсу**, а продовжувати виконувати її оригінальні `libunity.so` та `libil2cpp.so`. Реверс використовувати для побудови мінімальних JNI-заглушок і точкових ARM64-патчів. Це значно реальніше, ніж відновлювати всю карткову гру з машинного коду.

Оцінка:

- проаналізувати правила та внутрішню архітектуру: висока реалістичність;
- знайти й відключити рекламу/аналітику/IAP: висока;
- зробити офлайн-wrapper із точковими патчами: середньо-висока;
- повністю відновити Unity-проєкт: практично нереально;
- переписати гру на основі відновленої логіки: можливо, але це вже окремий великий порт.

Юридично безпечніша модель — не поширювати APK, `.so`, metadata чи assets, а розповсюджувати лише wrapper/патч, який вимагає власну легально отриману копію гри.

> а напиши як тоді краще реалізувати що гра запустилась на світч? і чи буде підтримка стіків

Найкращий шлях — **окремий per-title wrapper для Durak 25.0**, а не універсальний запуск APK. Основою я б узяв [`laytonbmr_nx`](https://github.com/NaGaa95/laytonbmr_nx), оскільки він уже працює з Android-версією Unity 6000/IL2CPP, близькою до Durak 6000.4.

## Запропонована архітектура

```text
durak_nx.nro
 ├─ ARM64 Android ELF loader
 ├─ Bionic/libc/libdl/liblog compatibility
 ├─ мінімальний JavaVM/JNI
 ├─ UnityPlayer lifecycle
 ├─ EGL/GLES3 → switch-mesa
 ├─ input → touch/controller
 ├─ audio та локальні збереження
 └─ заглушки реклами, billing, analytics
           ↓
      libmain.so
           ↓
      libunity.so
           ↓
      libil2cpp.so + global-metadata.dat
           ↓
       Unity assets
```

DEX виконувати не потрібно. Він потрібен переважно для Android Activity та сторонніх SDK, які wrapper замінить.

## Як реалізовувати поетапно

### 1. Зафіксувати конкретну версію

Wrapper має підтримувати тільки досліджений Durak 25.0:

- перевіряти SHA-256 `libunity.so`, `libil2cpp.so` і metadata;
- відмовлятися запускати невідому версію;
- усі адресні ARM64-патчі прив’язувати до цих хешів.

Це захистить від аварій після оновлення APK.

### 2. Підготувати файли гри

На SD-карті:

```text
sdmc:/switch/durak_nx/
├── durak_nx.nro
├── libmain.so
├── libunity.so
├── libil2cpp.so
├── libsqlite3.so
└── assets/
    └── bin/Data/
        ├── Managed/Metadata/global-metadata.dat
        ├── data.unity3d
        ├── sharedassets1.resource
        ├── boot.config
        └── ...
```

Wrapper може сам розпаковувати потрібні файли з `base.apk` і `split_config.arm64_v8a.apk`. Оригінальні файли гри не слід включати в дистрибутив wrapper.

### 3. Запустити native-бібліотеки

Потрібно:

1. Завантажити `libmain.so`.
2. Завантажити й релокувати `libunity.so`.
3. Завантажити `libil2cpp.so`.
4. Виконати `.init_array` і `JNI_OnLoad`.
5. Перехопити `RegisterNatives`, щоб отримати адреси:
   - `nativeInit`;
   - `nativeRender`;
   - `nativePause`/`nativeResume`;
   - `nativeFocusChanged`;
   - `nativeInjectEvent`;
   - інших методів конкретної Unity 6000.4.
6. Створити EGL/GLES3 surface через switch-mesa.
7. Запустити Unity render loop.

Залежності `libc`, `libm`, `libdl`, `liblog`, `libandroid`, `libmediandk` та EGL потрібно віддавати через таблицю сумісних Horizon-функцій.

### 4. Мінімальний fake Android/JNI

Повний Android не потрібен. Треба реалізувати лише класи й методи, які реально викликає гра:

- `UnityPlayer`;
- `Activity`, `Context`, `Application`;
- `AssetManager`;
- `Surface`, `Display`, `Window`;
- `Build`, `Build.VERSION`;
- файлові каталоги;
- locale, screen size, DPI;
- `SharedPreferences`;
- мінімальні `Handler`/`Looper`/`Choreographer`;
- мережевий статус.

Для сторонніх сервісів повертати безпечні результати:

- Appodeal: ініціалізація завершена, реклами немає;
- Billing: сервіс недоступний, покупок немає;
- Analytics: прийняти виклик і нічого не робити;
- Notifications: успішна заглушка;
- Advertising ID: порожній або фіксований локальний ID;
- Play Integrity/licensing: залежно від поведінки гри — нейтральний результат або точковий patch.

Важливо викликати callback-и. Просте ігнорування методу може залишити гру в нескінченному очікуванні.

### 5. Офлайн-режим

Потрібно простежити в IL2CPP:

- запуск головного меню;
- створення локальної партії;
- генерацію колоди;
- вибір ботів;
- завантаження локальних профілів;
- відкриття SQLite;
- PlayerPrefs;
- перевірки мережі, реклами й premium.

Мережеві екрани можна:

- приховати;
- зробити неактивними;
- повертати в меню;
- або змусити перевірку мережі відповідати `offline`.

Краще не видаляти SDK-код фізично — безпечніше заглушити JNI та поставити декілька перевірених ARM64-патчів.

## Чи працюватимуть стіки

Так. Для цієї карткової гри підтримка стіків цілком реальна.

Найпростіша схема:

| Елемент Switch | Дія |
|---|---|
| Лівий стік | Рух віртуального курсора |
| A | Торкання/вибір карти |
| B | Назад/скасування |
| X | Додаткова дія, наприклад «пас» |
| Y | «Взяти» або контекстна кнопка |
| D-pad | Переміщення між картами/кнопками |
| L/R | Перемикання між елементами |
| + | Пауза/меню |
| Сенсорний екран | Прямий touch без курсора |

Є два способи подати input у Unity:

1. **Через Unity Android input pipeline.** Wrapper створює fake `MotionEvent` і передає його через зареєстрований `nativeInjectEvent`. Це ближче до нормальної поведінки Android.

2. **Через IL2CPP hooks.** Перехоплюються `UnityEngine.Input.touchCount`, `GetTouch`, mouse position та mouse button. Це простіше, якщо fake `MotionEvent` у Unity 6000.4 виявиться складним.

Для Durak я б починав із:

- реального touchscreen;
- лівого стіка як миші;
- A як `touch down/up`;
- D-pad як snap-навігації між картами.

Перетворення стіка на touch:

```text
stick X/Y
   ↓ dead zone
швидкість курсора
   ↓
екранні координати
   ↓
finger down / move / up
   ↓
Unity UI EventSystem
```

Потрібні dead zone близько 12–18%, прискорення курсора і видимий cursor overlay. Правий стік для карткової гри, найімовірніше, не потрібен, але його можна використати для швидкого прокручування або альтернативного курсора.

## Рекомендований порядок роботи

1. Завантаження ELF без виконання гри.
2. Успішні `JNI_OnLoad` усіх трьох Unity-бібліотек.
3. Перший кадр Unity.
4. Touchscreen.
5. Вихід у головне меню.
6. Запуск локальної партії.
7. Аудіо.
8. Збереження і повторне завантаження.
9. Заглушення SDK та мережевих екранів.
10. Віртуальний курсор і кнопки Joy-Con.
11. Лише після цього — покращена D-pad навігація.

Запускати такий NRO потрібно через **title override/full-memory mode**, а не через Album applet. Підтримка стіків не є головною проблемою — найскладніша частина буде в запуску Unity 6000.4 та правильному JNI lifecycle.

> як ти оціниш цю роботу. чи можеш її виконати? і в чому може бути проблема?

Так, я можу взятися за реалізацію, але це складний експериментальний порт, а не звичайне «перепакування APK».

## Моя оцінка

- Загальна складність: **8/10**
- Шанс отримати перший кадр/головне меню: **високий, близько 70–80%**
- Шанс отримати стабільну локальну партію: **приблизно 60–70%**
- Повністю відполірована версія зі збереженням, звуком і Joy-Con: залежить від результатів тестування на реальному Switch.

Орієнтовний обсяг для одного досвідченого розробника:

| Етап | Орієнтир |
|---|---:|
| Повний reverse/API-аудит | 2–5 днів |
| Адаптація Unity 6 loader | 1–3 тижні |
| Перший кадр і меню | 1–4 тижні |
| Локальна партія | ще 1–4 тижні |
| Звук, збереження, контролер | ще 1–2 тижні |
| Виправлення нестабільності | непередбачувано |

Це не точний строк: одна несумісність у `libunity.so` може вирішитися за годину або забрати тиждень.

## Що я можу виконати

Я можу:

- зробити детальний реверс `libil2cpp.so`, metadata та JNI;
- знайти послідовність запуску Unity;
- взяти MIT-базу Unity-wrapper для Switch;
- адаптувати ELF loader під бібліотеки Durak;
- реалізувати Bionic/JNI/Android-заглушки;
- відключити рекламу, аналітику, billing і network-only функції;
- налаштувати GLES3, touch, Joy-Con і віртуальний курсор;
- реалізувати локальні файли, PlayerPrefs і SQLite;
- збирати `.nro`;
- додати детальне логування crash-адрес і unresolved symbols;
- ітеративно виправляти проблеми за логами з консолі.

Але я не можу сам фізично перевірити результат на вашому Switch. Для успіху потрібна співпраця:

1. Я готую чергову `.nro`-збірку.
2. Ви запускаєте її через title override.
3. Надсилаєте `debug.log`, crash report, фото або відео.
4. Я знаходжу причину та готую наступну збірку.

Без доступу до реального обладнання можна довести проєкт до стану «компілюється і теоретично правильно завантажує ELF», але не підтвердити рендеринг, input і стабільність.

## Найбільші потенційні проблеми

### 1. Конкретна версія Unity 6000.4

Схожий `laytonbmr_nx` використовує Unity 6000.0, але це не означає повну сумісність. Могли змінитися:

- порядок `RegisterNatives`;
- Java/JNI callbacks;
- структура UnityPlayer;
- Android lifecycle;
- графічна ініціалізація;
- IL2CPP metadata та startup;
- внутрішні офсети.

Імовірно, доведеться адаптувати wrapper саме під Durak 25.0.

### 2. Bionic проти Horizon

Android-бібліотеки розраховані на Bionic libc. Horizon homebrew використовує інше оточення. Особливо проблемні:

- `pthread` і TLS;
- mutex/condition ABI;
- `dlopen`/`dlsym`;
- exception unwinding;
- signals;
- clocks;
- файлові дескриптори;
- memory mapping і executable pages.

Некоректна структура mutex може спричинити crash далеко від справжньої причини.

### 3. Android lifecycle

Unity очікує:

- Activity;
- Surface;
- ANativeWindow;
- Choreographer;
- Looper/Handler threads;
- pause/resume/focus;
- callbacks із Java.

Якщо пропустити один callback, можливий чорний екран або зависання перед першим кадром.

### 4. Реклама може бути частиною startup flow

Рекламу можна не реалізовувати, але не завжди достатньо просто повернути `null`. Гра може чекати callback на кшталт:

```text
initialize completed
consent completed
configuration loaded
remote config completed
```

Треба відновити очікувану послідовність і викликати callback із результатом «недоступно/offline».

### 5. Графіка

Маніфест вимагає GLES 3.0. Можливі проблеми:

- відмінності EGL;
- формати текстур;
- shader compilation;
- framebuffer orientation;
- clipping/scissor;
- sRGB;
- UI scaling;
- portrait/landscape;
- відео або WebView-елементи.

Для звичайної 2D-карткової гри ризик нижчий, ніж для складної 3D-гри.

### 6. Пам’ять

`libunity.so` і `libil2cpp.so` разом займають понад 52 МБ, плюс assets і runtime. Потрібен full-memory title override. Запуск через Album майже напевно не підійде.

### 7. Збереження

У грі присутні `SimpleSQL` і `libsqlite3.so`. Потрібно правильно відтворити Android-шляхи:

```text
/data/data/ru.appscraft.durak/app_data/
/data/data/ru.appscraft.durak/shared_prefs/
```

і перенаправити їх у:

```text
sdmc:/switch/durak_nx/save/
```

Потрібно перевірити коректне завершення транзакцій та flush перед виходом.

### 8. Input

Стіки реалізувати можна. Але найнадійніший перший етап — touchscreen. Потім:

- лівий стік → віртуальний курсор;
- A → touch;
- B → назад;
- D-pad → вибір карт;
- кнопки → дії столу.

Проблема може виникнути, якщо гра читає touch через новий внутрішній Unity Input pipeline, а не стандартний `nativeInjectEvent`. Тоді знадобляться IL2CPP hooks.

## Як варто починати

Не варто одразу будувати повний wrapper. Спочатку потрібен короткий proof of concept із чіткими контрольними точками:

1. ELF-бібліотеки завантажуються без unresolved symbols.
2. `JNI_OnLoad` працює.
3. Unity реєструє native methods.
4. IL2CPP читає `global-metadata.dat`.
5. З’являється перший кадр.
6. Працює touchscreen.
7. Відкривається локальна партія.

Якщо проєкт доходить до першого кадру — подальша робота вже обґрунтована. Якщо блокер з’явиться раніше на фундаментальному рівні Unity/Bionic, можна зупинитися без витрат на контролери, збереження та UI.

Моя рекомендація: **братися, але спочатку як обмежений PoC “перший кадр + touch + локальна партія”**. Після цього вже приймати рішення про повноцінний порт.

> Продовжуємо тільки аналіз. Нічого поки не реалізовуй.
>
> Візьми за основний референс проєкт laytonbmr\_nx і порівняй його з Durak 25.0.
>
> Мета — зрозуміти, наскільки реально адаптувати laytonbmr\_nx під Durak.
>
> Потрібно:
>
> - порівняти версії Unity та структуру native-бібліотек;
> - порівняти imports/exports libmain.so, libunity.so і libil2cpp.so;
> - визначити, які Android/JNI/NDK API вже реалізовані в laytonbmr\_nx;
> - визначити, яких API конкретно не вистачає для Durak;
> - окремо перевірити графіку, audio, input/touch, filesystem і lifecycle;
> - визначити, які рекламні/analytics/billing залежності можна просто заглушити для офлайн-гри;
> - знайти потенційні блокери, через які Durak може не запуститися навіть після адаптації.
>
> Нічого не програмуй.
>
> Наприкінці дай:
>
> 1. Наскільки laytonbmr\_nx підходить як база.
> 2. Що можна перевикористати без змін.
> 3. Що доведеться адаптувати.
> 4. Що доведеться написати додатково.
> 5. Який найбільший технічний ризик.
> 6. Приблизний обсяг роботи до першого запуску меню гри.

<details><summary>7 previous messages</summary>

> Продовжу лише статичний аналіз. Завантажу вихідний код `laytonbmr_nx` у тимчасову папку, розберу його loader/JNI/NDK shim і зіставлю з уже витягнутими бібліотеками Durak. Окремо позначу, де порівняння обмежене тим, що репозиторій Layton не містить пропрієтарних `.so`.
>
> <details><summary>Explored 14 files, a search, a list, ran 5 commands</summary>
>
> - Ran `tmp_ref=$(mktemp -d /tmp/layton-ref.XXXXXX); git clone --depth 1 https://github.com/NaGaa95/laytonbmr_nx.git "$tmp_ref"; echo "$tmp_ref"; rg --files "$tmp_ref" | sort`
>
> - Ran `tmp_ref=/tmp/layton-ref.YmMVGm; rmdir "$tmp_ref" 2>/dev/null || true; /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/git clone --depth 1 https://github.com/NaGaa95/laytonbmr_nx.git "$tmp_ref"; echo "$tmp_ref"; rg --files "$tmp_ref" | sort`
>
> - Ran `wc -l /tmp/layton-ref.YmMVGm/source/* /tmp/layton-ref.YmMVGm/Makefile /tmp/layton-ref.YmMVGm/README.md | sort -n; sed -n '1,260p' /tmp/layton-ref.YmMVGm/README.md; sed -n '1,280p' /tmp/layton-ref.YmMVGm/Makefile`
>
> <details><summary>Explored 4 files</summary>
>
> - Read `/tmp/layton-ref.YmMVGm/source/unity_imports.c`
> - Read `/tmp/layton-ref.YmMVGm/source/android_native_unity.c`
> - Read `/tmp/layton-ref.YmMVGm/source/unity_input_hook.c`
> - Read `/tmp/layton-ref.YmMVGm/source/unity_entrypoints.h`
>
> </details>
>
> - Ran `rg -n "DynLibFunction|resolve_imports|so_resolve|unity_dynlib|dynlib_functions|load_module|libmain|libunity|libil2cpp|JNI_OnLoad|nx_install" /tmp/layton-ref.YmMVGm/source/{main.c,imports.c,imports.h,so_util.c,unity_imports.c} | sed -n '1,320p'`
>
> <details><summary>Explored 4 files</summary>
>
> - Read `/tmp/layton-ref.YmMVGm/source/main.c`
> - Read `/tmp/layton-ref.YmMVGm/source/main.c`
> - Read `/tmp/layton-ref.YmMVGm/source/so_util.c`
> - Read `/tmp/layton-ref.YmMVGm/source/imports.c`
>
> </details>
>
> - Ran `PYTHONPATH=/tmp/durak-pytools /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> import re
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> src=Path('/tmp/layton-ref.YmMVGm/source')
> mapped=set()
> for p in src.glob('*'):
>  if p.suffix not in ('.c','.h','.inc'): continue
>  t=p.read_text(errors='ignore')
>  mapped.update(re.findall(r'\{\s*"([A-Za-z0-9_.$@]+)"\s*,\s*\(uintptr_t\)',t))
>  # SL IIDs generated by macro
> for n in re.findall(r'SL_IID\(([A-Z0-9_]+)\)',(src/'imports.c').read_text()): mapped.add('SL_IID_'+n)
> print('Layton explicit shim symbols',len(mapped))
> root=Path('/tmp/durak-analysis.FeTqD3/arm64/lib/arm64-v8a')
> mods={}
> exports=set()
> for name in ['libmain.so','libunity.so','libil2cpp.so']:
>  p=root/name
>  with p.open('rb') as f:
>   e=ELFFile(f); ds=e.get_section_by_name('.dynsym'); imp={}; exp=set()
>   for s in ds.iter_symbols():
>    if not s.name: continue
>    if s['st_shndx']=='SHN_UNDEF': imp[s.name]=s['st_info']['bind']
>    elif s['st_info']['bind']!='STB_LOCAL': exp.add(s.name)
>   mods[name]=(imp,exp); exports |= exp
> for name,(imp,exp) in mods.items():
>  miss=sorted(k for k in imp if k not in mapped and k not in exports)
>  weak=sorted(k for k in miss if imp[k]=='STB_WEAK')
>  strong=sorted(k for k in miss if imp[k]!='STB_WEAK')
>  cover=sum(1 for k in imp if k in mapped)
>  cross=sum(1 for k in imp if k not in mapped and k in exports)
>  print(f'\n{name}: imports={len(imp)} exports={len(exp)} shim={cover} cross-module={cross} missing={len(miss)} strong={len(strong)} weak={len(weak)}')
>  print('STRONG MISSING')
>  print('\n'.join(strong) if strong else '(none)')
>  print('WEAK MISSING')
>  print('\n'.join(weak) if weak else '(none)')
>  print('EXPORTED JNI/Unity/IL2CPP')
>  cand=[x for x in sorted(exp) if x.startswith(('JNI','Java_','Unity','il2cpp'))]
>  print('\n'.join(cand[:300]))
> PY`
>
> <details><summary>Explored 8 files, a search, a list</summary>
>
> - Listed files in `Data`
> - Read `/tmp/layton-ref.YmMVGm/source/unity_glue.c`
> - Read `/tmp/layton-ref.YmMVGm/source/unity_jni.c`
> - Read `/tmp/layton-ref.YmMVGm/source/firebase_stub.c`
> - Read `/tmp/layton-ref.YmMVGm/source/unity_jni.h`
> - Read `/tmp/layton-ref.YmMVGm/source/unity_jni_surface.h`
> - Read `/tmp/layton-ref.YmMVGm/source/jni_unimpl.h`
> - Searched for `strcmp\(.*cls|strstr\(.*cls|has\(cls|FindClass|GetMethodID|GetStaticMethodID|RegisterNatives|Call[A-Za-z]+Method|NewString|Build|Choreographer|AudioTrack|PackageManager|Connectivity|Uri|Locale|System` in `jni_fake.c`
> - Read `/tmp/layton-ref.YmMVGm/source/jni_fake.c`
> - Read `/tmp/layton-ref.YmMVGm/source/jni_fake.c`
>
> </details>
>
> </details>
>
> Context compaction
>
> Source: automatic
> Status: completed
>
> Зараз завершую порівняння на рівні ELF/JNI: перевірю точні native-методи Unity 6000.4 у Durak, категорії імпортів (графіка/audio/input/filesystem) та формат релокацій. Це дозволить відокремити те, що справді вже покриває `laytonbmr_nx`, від речей, які лише схожі концептуально.
>
> <details><summary>Explored 3 files, ran 11 commands</summary>
>
> - Ran `git rev-parse HEAD && git log -1 --format='%cI %s' && pwd && rg -n "UNITY_JNI_CLASSES|fseeko64|ftello64|remainderf|AMedia|AChoreographer|ASensor|ANativeWindow|AAsset|OpenSLES|SL_IID|nativeRender|nativeInjectEvent" source include README.md`
>
> - Ran `pwd; ls -la; command -v rg; command -v readelf; command -v llvm-readelf; command -v python3; find /Applications -path '*bin/git' -type f 2>/dev/null | head -5`
>
> - Ran `/Applications/Sourcetree.app/Contents/Resources/git_local/bin/git rev-parse HEAD; /Applications/Sourcetree.app/Contents/Resources/git_local/bin/git log -1 --format='%cI %s'; /Applications/ChatGPT.app/Contents/Resources/rg -n "UNITY_JNI_CLASSES|fseeko64|ftello64|remainderf|AMedia|AChoreographer|ASensor|ANativeWindow|AAsset|OpenSLES|SL_IID|nativeRender|nativeInjectEvent" source README.md`
>
> - Ran `find /tmp -maxdepth 3 \( -name 'libunity.so' -o -name 'libil2cpp.so' -o -name 'libmain.so' -o -name 'base.apk' \) -print 2>/dev/null; find '/Users/oleksandrbazavliak/Documents/Durak Mod' -maxdepth 3 -type f -print`
>
> - Ran `tmpdir=$(mktemp -d /tmp/durak25.XXXXXX); unzip -q '/Users/oleksandrbazavliak/Documents/Durak Mod/Durak_25.0.apks' -d "$tmpdir"; mkdir "$tmpdir/base" "$tmpdir/arm64"; unzip -q "$tmpdir/base.apk" -d "$tmpdir/base"; unzip -q "$tmpdir/split_config.arm64_v8a.apk" -d "$tmpdir/arm64"; printf '%s\n' "$tmpdir"; find "$tmpdir" -path '*/lib/arm64-v8a/*.so' -print; python3 - <<'PY'
> try:
>  import elftools; print('pyelftools',elftools.__version__)
> except Exception as e: print('pyelftools unavailable',e)
> try:
>  import androguard; print('androguard',androguard.__version__)
> except Exception as e: print('androguard unavailable',e)
> PY`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> for m in ('elftools','androguard'):
>  try:
>   x=__import__(m); print(m,getattr(x,'__version__','ok'))
>  except Exception as e: print(m,'unavailable',repr(e))
> PY
> command -v unzip; command -v nm; command -v objdump; find /Users/oleksandrbazavliak/.cache/codex-runtimes -type f \( -name 'llvm-readelf' -o -name 'readelf' -o -name 'llvm-nm' \) 2>/dev/null | head -20`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" -m pip install --quiet --target /tmp/durak-analysis-py pyelftools androguard`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> root=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')
> for name in ('libmain.so','libunity.so','libil2cpp.so'):
>  p=root/name
>  with p.open('rb') as f:
>   e=ELFFile(f)
>   print('\n##',name)
>   print('machine',e['e_machine'],'type',e['e_type'],'entry',hex(e['e_entry']),'sections',e.num_sections(),'segments',e.num_segments())
>   dyn=e.get_section_by_name('.dynamic')
>   print('NEEDED', [t.needed for t in dyn.iter_tags('DT_NEEDED')])
>   tags=[]
>   for t in dyn.iter_tags():
>    if t.entry.d_tag in ('DT_RELA','DT_RELASZ','DT_RELR','DT_RELRSZ','DT_ANDROID_RELA','DT_ANDROID_RELASZ','DT_INIT','DT_INIT_ARRAY','DT_INIT_ARRAYSZ','DT_SONAME'):
>     tags.append((t.entry.d_tag, hex(t.entry.d_val) if isinstance(t.entry.d_val,int) else str(t.entry)))
>   print('dynamic',tags)
>   print('reloc sections',[(s.name,s.num_relocations()) for s in e.iter_sections() if hasattr(s,'num_relocations')])
>   ds=e.get_section_by_name('.dynsym')
>   imports=[]; exports=[]
>   for s in ds.iter_symbols():
>    bind=s['st_info']['bind']; typ=s['st_info']['type']; vis=s['st_other']['visibility']
>    if s['st_shndx']=='SHN_UNDEF' and bind in ('STB_GLOBAL','STB_WEAK'):
>     imports.append((s.name,bind,typ))
>    elif s.name and s['st_shndx']!='SHN_UNDEF' and bind in ('STB_GLOBAL','STB_WEAK') and vis=='STV_DEFAULT':
>     exports.append((s.name,bind,typ))
>   print('imports',len(imports),'strong',sum(x[1]=='STB_GLOBAL' for x in imports),'exports',len(exports))
>   cats={'android_window':[],'choreographer':[],'looper_input':[],'sensor':[],'asset':[],'media':[],'egl_gles':[],'audio_sl':[],'fs':[],'dl':[],'pthread':[]}
>   for n,b,t in imports:
>    if n.startswith('ANativeWindow'): cats['android_window'].append(n)
>    if n.startswith('AChoreographer'): cats['choreographer'].append(n)
>    if n.startswith(('ALooper','AInput','AMotion','AKeyEvent')): cats['looper_input'].append(n)
>    if n.startswith(('ASensor','ASensorManager')): cats['sensor'].append(n)
>    if n.startswith('AAsset'): cats['asset'].append(n)
>    if n.startswith('AMedia'): cats['media'].append(n)
>    if n.startswith(('egl','gl')): cats['egl_gles'].append(n)
>    if n.startswith(('sl','SL_')): cats['audio_sl'].append(n)
>    if n in ('open','open64','close','read','write','lseek','lseek64','fopen','fopen64','fclose','fread','fwrite','fseek','fseeko','fseeko64','ftell','ftello','ftello64','stat','stat64','fstat','fstat64','mkdir','unlink','rename','opendir','readdir','closedir','access','realpath','mmap','munmap'): cats['fs'].append(n)
>    if n.startswith('dl'): cats['dl'].append(n)
>    if n.startswith('pthread'): cats['pthread'].append(n)
>   for k,v in cats.items():
>    if v: print(k,len(v),sorted(set(v)))
>   if name=='libunity.so':
>    print('exports list',[x[0] for x in exports])
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> import re
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> repo=Path('/tmp/layton-ref.YmMVGm/source')
> covered=set()
> for p in repo.glob('*'):
>  if p.suffix in ('.c','.h','.inc'):
>   txt=p.read_text(errors='ignore')
>   covered.update(re.findall(r'\{\s*"([A-Za-z_][A-Za-z0-9_.$@]*)"\s*,',txt))
> root=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')
> print('explicit named shim entries',len(covered))
> for name in ('libmain.so','libunity.so','libil2cpp.so','libsqlite3.so','libsigner.so','libsentry.so','libsentry-android.so','libdatastore_shared_counter.so','libapplovin-native-crash-reporter.so'):
>  with (root/name).open('rb') as f:
>   e=ELFFile(f); ds=e.get_section_by_name('.dynsym')
>   imp=[]
>   for s in ds.iter_symbols():
>    if s['st_shndx']=='SHN_UNDEF' and s['st_info']['bind']=='STB_GLOBAL': imp.append(s.name)
>   missing=sorted(set(imp)-covered)
>   print(name,'strong imports',len(imp),'missing explicit',len(missing),missing[:100])
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> from androguard.core.dex import DEX
> base=Path('/tmp/durak25.RMJCfl/base')
> for dexfile in sorted(base.glob('classes*.dex')):
>  d=DEX(dexfile.read_bytes())
>  for c in d.get_classes():
>   n=c.get_name()
>   if n in ('Lcom/unity3d/player/UnityPlayer;','Lcom/unity3d/player/NativeLoader;') or 'FMOD' in n:
>    print('\n',dexfile.name,n)
>    for m in c.get_methods():
>     if m.get_access_flags() & 0x100:
>      print(m.get_name(),m.get_descriptor(),m.get_access_flags_string())
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from loguru import logger
> logger.remove()
> from pathlib import Path
> from androguard.core.dex import DEX
> base=Path('/tmp/durak25.RMJCfl/base')
> for dexfile in sorted(base.glob('classes*.dex')):
>  d=DEX(dexfile.read_bytes())
>  for c in d.get_classes():
>   methods=[m for m in c.get_methods() if m.get_access_flags() & 0x100]
>   if methods and (c.get_name().startswith('Lcom/unity3d/') or c.get_name().startswith('Lorg/fmod/')):
>    print(dexfile.name,c.get_name())
>    for m in methods: print(' ',m.get_name(),m.get_descriptor())
> PY`
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./source/unity_entrypoints.h`
> - Read `./source/unity_jni_surface.h`
> - Read `./README.md`
>
> </details>
>
> </details>
>
> Проміжний результат уже суттєвий: сам ELF-loader майже підходить — для трьох основних бібліотек Durak бракує лише `fseeko64`, `ftello64` і `remainderf`. Але Unity ABI вже змінився: у Durak `initJni(Context,int,String)` замість `initJni(Context,int)`, а `nativeInjectEvent(InputEvent,int)` замість старої сигнатури. Тобто готові адреси та lifecycle-виклики Layton напряму використати не можна.
>
> <details><summary>Explored 9 files, 2 lists, ran 21 commands, searched the web</summary>
>
> <details><summary>Explored 3 files, 2 lists</summary>
>
> - Listed files in `assets`
> - Listed files in `assets`
> - Read `./base/assets/bin/Data/boot.config`
> - Read `./base/assets/bin/Data/RuntimeInitializeOnLoads.json`
> - Read `./base/assets/bin/Data/ScriptingAssemblies.json`
>
> </details>
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> import re
> from pathlib import Path
> files=[Path('/tmp/durak25.RMJCfl/base/assets/bin/Data/Managed/Metadata/global-metadata.dat'),Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so'),Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libunity.so')]
> prefixes=('android.','com.android.','com.appodeal.','com.google.','com.unity3d.','com.adjust.','com.appsflyer.','io.sentry.','io.appmetrica.','ru.yandex.','org.fmod.','java.','javax.')
> for p in files:
>  b=p.read_bytes(); vals=set()
>  for m in re.finditer(rb'[ -~]{5,300}',b):
>   s=m.group().decode('ascii','ignore')
>   for tok in re.split(r'[^A-Za-z0-9_.$/:-]+',s):
>    dotted=tok.replace('/','.')
>    if dotted.startswith(prefixes) and len(dotted)<180: vals.add(dotted.strip('.'))
>  print('\n##',p.name,len(vals))
>  for s in sorted(vals): print(s)
> PY`
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n "FindClass|find_class|UNITY_JNI_CLASSES|GetMethodID|Call.*Method|unknown class|unhandled" source/jni_fake.c source/unity_jni.c source/unity_glue.c | head -160; sed -n '1,260p' source/jni_fake.c`
>
> <details><summary>Explored 2 files</summary>
>
> - Read `./source/jni_fake.c`
> - Read `./source/jni_fake.c`
>
> </details>
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> root=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')
> for p in sorted(root.glob('*.so')):
>  with p.open('rb') as f:
>   e=ELFFile(f); loads=[s for s in e.iter_segments() if s['p_type']=='PT_LOAD']
>   start=min(x['p_vaddr'] for x in loads); end=max(x['p_vaddr']+x['p_memsz'] for x in loads)
>   print(f'{p.name:42} file={p.stat().st_size/1048576:7.2f} MiB span={(end-start)/1048576:7.2f} MiB alignmax={max(x["p_align"] for x in loads):#x}')
> PY
> rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n "SO_MEM|REGION|224|memory|overcommit|load_addr|LOAD_ADDRESS" source/main.c source/so_util.c Makefile | head -180`
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n "224|SO_|REGION|region|overcommit|LOAD_ADDRESS|MEM" source/main.c source/so_util.c Makefile | head -220`
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n "globalgamemanagers|level0|data\.unity3d|check_data|AAssetManager_open|basename|assets/bin/Data|boot.config" source/*.c source/*.h README.md`
>
> Searched the web for `https://github.com/NaGaa95/laytonbmr_nx`
>
> - Ran `sed -n '1,125p' source/main.c; sed -n '620,930p' source/main.c; sed -n '1,130p' source/imports.c; sed -n '1,130p' source/firebase_stub.c 2>/dev/null || true; ls source`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> for name in ('libmain.so','libunity.so','libil2cpp.so'):
>  p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')/name
>  with p.open('rb') as f:
>   e=ELFFile(f); ds=e.get_section_by_name('.dynsym'); xs=[]
>   for s in ds.iter_symbols():
>    if s.name and s['st_shndx']!='SHN_UNDEF' and s['st_info']['bind'] in ('STB_GLOBAL','STB_WEAK') and s['st_other']['visibility']=='STV_DEFAULT': xs.append(s.name)
>   print('\n',name,len(xs))
>   if name!='libil2cpp.so': print('\n'.join(xs))
>   else:
>    keep=[x for x in xs if x=='JNI_OnLoad' or x.startswith('il2cpp_gc_') or x in ('il2cpp_string_new','il2cpp_init','il2cpp_shutdown') or x.startswith('UnityAds')]
>    print('\n'.join(sorted(keep)))
> PY`
>
> - Ran `for f in /tmp/durak25.RMJCfl/base/assets/bin/Data/Managed/Metadata/global-metadata.dat /tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so; do echo "$f"; LC_ALL=C /usr/bin/strings -a "$f" 2>/dev/null | rg -i 'sqlite|appodeal|purchas|billing|analytics|appsflyer|adjust|sentry|appmetrica|remote.?config' | head -200; done`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> from pathlib import Path
> for fp in ['/tmp/durak25.RMJCfl/base/assets/bin/Data/Managed/Metadata/global-metadata.dat','/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so']:
>  b=Path(fp).read_bytes(); print(fp)
>  for needle in [b'sqlite',b'Appodeal',b'appodeal',b'Purchas',b'Billing',b'Analytics',b'AppsFlyer',b'Adjust',b'Sentry',b'AppMetrica',b'RemoteConfig']:
>   poss=[]; start=0
>   while True:
>    i=b.lower().find(needle.lower(),start)
>    if i<0: break
>    poss.append(i); start=i+1
>   print(needle.decode(),len(poss),poss[:10])
>   for i in poss[:3]:
>    lo=max(0,i-80); hi=min(len(b),i+160); s=''.join(chr(c) if 32<=c<127 else ' ' for c in b[lo:hi]); print(' ',s)
> PY`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> from pathlib import Path
> import re
> for p in sorted(Path('/tmp/durak25.RMJCfl/base').glob('classes*.dex')):
>  b=p.read_bytes(); hits=[]
>  for needle in (b'signer',b'sentry',b'datastore_shared_counter',b'applovin-native-crash-reporter',b'sqlite3',b'il2cpp',b'unity'):
>   if needle.lower() in b.lower(): hits.append(needle.decode())
>  if hits: print(p.name,hits)
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> root=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')
> for name in ('libsqlite3.so','libsigner.so','libsentry.so','libsentry-android.so','libdatastore_shared_counter.so','libapplovin-native-crash-reporter.so'):
>  with (root/name).open('rb') as f:
>   e=ELFFile(f); ds=e.get_section_by_name('.dynsym'); xs=[]
>   for s in ds.iter_symbols():
>    if s.name and s['st_shndx']!='SHN_UNDEF' and s['st_info']['bind'] in ('STB_GLOBAL','STB_WEAK') and s['st_other']['visibility']=='STV_DEFAULT': xs.append(s.name)
>   print('\n',name,'exports',len(xs)); print('\n'.join(xs[:120]))
> PY`
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n "dlopen_fake|dlsym_fake|Firebase|libOpenSLES|module|loaded_modules|so_try_find|dlopen" source/libc_shim.c source/so_util.c source/imports.c source/main.c | head -240`
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./source/libc_shim.c`
> - Read `./source/main.c`
> - Read `./source/so_util.c`
>
> </details>
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> for name in ('libunity.so','libil2cpp.so'):
>  p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')/name
>  with p.open('rb') as f:
>   ds=ELFFile(f).get_section_by_name('.dynsym')
>   print(name,[(s.name,s['st_info']['type']) for s in ds.iter_symbols() if s['st_shndx']=='SHN_UNDEF' and s['st_info']['bind']=='STB_WEAK'])
> PY`
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n "gDeferredAction|STB_WEAK|weak" source`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> from pathlib import Path
> import re
> for fp in ['/tmp/durak25.RMJCfl/base/assets/bin/Data/Managed/Metadata/global-metadata.dat','/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so']:
>  b=Path(fp).read_bytes(); names=sorted(set(x.decode() for x in re.findall(rb'sqlite3_[A-Za-z0-9_]+',b)))
>  print(Path(fp).name,len(names)); print(' '.join(names))
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from loguru import logger; logger.remove()
> from androguard.core.apk import APK
> p=APK('/tmp/durak25.RMJCfl/base.apk')
> print('package',p.get_package(),'min',p.get_min_sdk_version(),'target',p.get_target_sdk_version())
> print('main',p.get_main_activity())
> print('permissions',sorted(p.get_permissions()))
> xml=p.get_android_manifest_xml()
> ns='{http://schemas.android.com/apk/res/android}'
> for a in xml.iter('activity'):
>  print('activity',a.get(ns+'name'),'orientation',a.get(ns+'screenOrientation'),'configChanges',a.get(ns+'configChanges'),'resizeable',a.get(ns+'resizeableActivity'))
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from loguru import logger; logger.remove()
> from androguard.core.apk import APK
> p=APK('/tmp/durak25.RMJCfl/base.apk'); x=p.get_android_manifest_xml(); ns='{http://schemas.android.com/apk/res/android}'
> for e in x.iter('uses-feature'):
>  print({k.split('}')[-1]:v for k,v in e.attrib.items()})
> PY`
>
> <details><summary>Explored 2 files</summary>
>
> - Read `./source/unity_input_hook.c`
> - Read `./source/android_native_unity.c`
>
> </details>
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> for name in ('libmain.so','libunity.so','libil2cpp.so','libsqlite3.so'):
>  with (Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')/name).open('rb') as f:
>   e=ELFFile(f); n=e.get_section_by_name('.note.gnu.build-id'); print(name, n.data().hex() if n else 'none')
> PY
> PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> from pathlib import Path
> for p in [Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libunity.so'),Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so')]:
>  b=p.read_bytes()
>  for q in [b'6000.4.0b6',b'6000.0.58f2']:
>   print(p.name,q.decode(),b.find(q))
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from loguru import logger; logger.remove()
> from pathlib import Path
> from androguard.core.dex import DEX
> p=Path('/tmp/durak25.RMJCfl/base/classes5.dex'); d=DEX(p.read_bytes())
> for c in d.get_classes():
>  if c.get_name().startswith('Lcom/unity3d/player/'):
>   for m in c.get_methods():
>    code=m.get_code()
>    if not code: continue
>    ins=list(code.get_bc().get_instructions())
>    if any('initJni' in i.get_output() or 'nativeInjectEvent' in i.get_output() for i in ins):
>     print('\n',c.get_name(),m.get_name(),m.get_descriptor())
>     for i in ins: print(f'{i.get_name():24} {i.get_output()}')
> PY`
>
> - Ran `/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/git tag -l; /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/git branch -a; /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/git log --oneline -8`
>
> - Ran `xxd -l 128 /tmp/durak25.RMJCfl/base/assets/bin/Data/data.unity3d; xxd -l 96 /tmp/durak25.RMJCfl/base/assets/bin/Data/Managed/Metadata/global-metadata.dat; stat -f '%N %z' /tmp/durak25.RMJCfl/base/assets/bin/Data/data.unity3d`
>
> </details>
</details>

Висновок: `laytonbmr_nx` — добра технічна база, але не готовий універсальний Unity-wrapper. Для Durak можна перевикористати більшу частину ELF/Android-сумісності, проте всі адреси патчів, Unity JNI entry points і частину lifecycle доведеться відновити заново.

Аналіз виконано для [Durak_25.0.apks](<./Durak_25.0.apks>) і `laytonbmr_nx` tag `1.0.1`, commit `5763d239`.

Важливе обмеження: репозиторій юридично не містить оригінальних Layton `.so`, тому точне binary-to-binary порівняння імпортів двох ігор неможливе. Я порівняв Durak із фактичним набором символів і API, які реалізує wrapper. Це відповідає структурі самого проєкту: оригінальні бібліотеки користувач має витягувати самостійно. [README laytonbmr_nx](https://github.com/NaGaa95/laytonbmr_nx/tree/5763d239f03e57447832bcb1450a3ac1099846c7)

## Unity і структура бібліотек

| Параметр | laytonbmr_nx | Durak 25.0 |
|---|---|---|
| Unity | `6000.0.58f2` | `6000.4.0b6` |
| Backend | IL2CPP | IL2CPP |
| ABI | ARM64 | тільки `arm64-v8a` |
| Основні бібліотеки | `libmain`, `libunity`, `libil2cpp` | ті самі |
| Дані Unity | окремі `globalgamemanagers`, `level0…` | `data.unity3d` UnityFS |
| Metadata | IL2CPP | `global-metadata.dat`, format 39 |
| Додаткові native libs | немає в базовому сценарії | SQLite та SDK-бібліотеки |

Durak має:

- `libil2cpp.so` — 31.3 MB;
- `libunity.so` — 21.4 MB;
- `libmain.so` — 6.7 KB;
- `libsqlite3.so`;
- `libsigner.so` — Adjust signature SDK;
- `libsentry.so`, `libsentry-android.so`;
- `libapplovin-native-crash-reporter.so`;
- `libdatastore_shared_counter.so`.

Архітектура ігор дуже схожа. Але перехід із Unity `6000.0` на `6000.4` уже змінив JNI ABI, тому близькість номера версії не означає сумісність адрес чи сигнатур.

## Imports/exports основних бібліотек Durak

| Бібліотека | Imports | Exports | Покриття laytonbmr_nx |
|---|---:|---:|---|
| `libmain.so` | 12 | 1 | 12/12 |
| `libunity.so` | 342, з них 340 strong | 7 | 339/342 |
| `libil2cpp.so` | 277 | 2414 | 277/277 |

У `libmain.so` єдиний export — `JNI_OnLoad`.

Exports `libunity.so`:

- `JNI_OnLoad`
- `JNI_OnUnload`
- `UnitySendMessage`
- `UnityInitialize`
- `UnityShutdown`
- `UnitySwappy_version`
- `UnitySwappy_injectTracer`

У `libil2cpp.so` присутні повний публічний IL2CPP API, `JNI_OnLoad`, `il2cpp_init`, `il2cpp_string_new`, GC-функції та `UnityAdsEngine*`.

Для трьох основних бібліотек wrapper не покриває лише:

- `fseeko64`
- `ftello64`
- `remainderf`

Це невеликі libc/libm-сумісні функції й самі по собі не є серйозною проблемою.

ELF-формат також сумісний із loader’ом: Durak використовує звичайні AArch64 RELA relocation sections, які `so_util.c` уже обробляє. [so_util.c](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/so_util.c)

### SQLite

Durak через SimpleSQL реально звертається щонайменше до 30 `sqlite3_*` функцій: `sqlite3_open`, `prepare_v2`, `step`, `bind_*`, `column_*`, `finalize` тощо. Це не SDK, який можна заглушити.

Для завантаження APK-версії `libsqlite3.so` у wrapper бракує:

- `asprintf`
- `fchown`
- `mremap`

Також бібліотека має 64-KB segment alignment, тоді як поточний loader просуває модулі з кроком 4 KB. Це треба перевірити й, імовірно, адаптувати.

## Критична різниця в Unity JNI ABI

У Layton:

```text
initJni(Context, int)
nativeInjectEvent(InputEvent)
```

У Durak:

```text
initJni(Context, int, String)
nativeInjectEvent(InputEvent, int)
```

Durak також має додаткові/оновлені natives:

- `nativeViewPaddingChanged`
- `nativeGetMainWindowIndex`
- `nativeCrashNow`
- `nativeOnApplyWindowInsets`
- `nativeReportKeyboardConfigChanged`
- `nativeUnityPlayerForGameActivityInitialized`
- розширений accessibility interface.

`laytonbmr_nx` використовує 32 entry points із жорстко прописаними RVA для конкретного `libunity.so`. Автор прямо зазначає, що адреси змінюються в кожному build і мають відновлюватися повторно. [unity_entrypoints.h](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/unity_entrypoints.h)

Для Durak необхідно заново знайти:

- таблиці `RegisterNatives`;
- адреси lifecycle-функцій;
- внутрішні IL2CPP JavaVM globals;
- `TimeManager::Update`;
- Choreographer/Swappy точки;
- memory-region патчі;
- Input і PlayerPrefs methods;
- FMOD output selection.

Старі RVA застосовувати не можна — це гарантовано дасть crash або пошкодження пам’яті.

## Що вже реалізує laytonbmr_nx

Wrapper уже має дуже значну частину потрібного середовища:

- ARM64 ELF loader, relocations та міжмодульний symbol resolution;
- Bionic-compatible libc/pthread/TLS/file/mmap shims;
- `dlopen`/`dlsym` для вже завантажених модулів;
- fake JavaVM/JNIEnv і більшість JNI table slots;
- Java strings, arrays, classes, methods, fields і `RegisterNatives`;
- `Context`, `Resources`, `Configuration`, `PackageManager`;
- `AssetManager`, InputStream і file descriptors;
- `SharedPreferences`;
- `ANativeWindow` поверх Switch `NWindow`;
- EGL/GLES через Mesa;
- `ALooper`;
- sensor API як безпечні заглушки;
- OpenSL ES shim поверх SDL2/libnx audio;
- touchscreen, Joy-Con input і віртуальний курсор;
- ручне керування Unity lifecycle;
- пам’ять/overcommit, bionic TLS;
- workaround для IL2CPP GC;
- власний clock і frame limiter.

[android_native_unity.c](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/android_native_unity.c) · [jni_fake.c](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/jni_fake.c)

## Аналіз за підсистемами

### Графіка

Ситуація сприятлива:

- Durak вимагає GLES 3.0;
- Vulkan у manifest позначений як optional;
- `libunity.so` імпортує стандартний EGL-набір;
- `ANativeWindow` і EGL уже реалізовані;
- гра має `screenOrientation=11`, тобто `userLandscape`, що збігається з landscape-моделлю Layton.

Найбільша проблема — frame pacing. Durak використовує `AChoreographer` і експортує Unity Swappy helpers. У Layton Choreographer вимикається version-specific патчем. Для Durak точку патча треба знайти заново, інакше `nativeRender` може зависнути в очікуванні Android-vsync.

### Audio

Durak використовує FMOD: у DEX присутні `FMODAudioDevice`, `fmodProcess` і `FmodAndroidAudioManager`.

OpenSL/SDL backend із Layton підходить концептуально. Але у Layton FMOD примусово перемикається на OpenSL патчем конкретної інструкції та конкретного enum. Ці значення не можна переносити в Durak без reverse engineering. Крім того, у вихідному коді Layton audio позначений як такий, що ще потребував перевірки на реальному залізі. [main.c](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/main.c)

Audio можна відкласти до моменту після першого меню.

### Input/touch і стіки

Підтримка стіків цілком реальна.

Layton уже реалізує:

- справжній touchscreen;
- лівий стік як віртуальний курсор;
- кнопку A як touch press;
- координатне масштабування;
- `Input.touchCount`, `GetTouch`, `mousePosition`, `GetMouseButton*`.

Але ці методи перехоплюються через конкретні IL2CPP RVA Layton. Для Durak адреси треба знайти заново та перевірити ABI структури `UnityEngine.Touch`.

Сам HID/virtual-cursor код можна залишити майже без змін. [unity_input_hook.c](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/unity_input_hook.c)

### Filesystem

Позитивні моменти:

- `data.unity3d` має стандартний заголовок `UnityFS`, не нестандартний зашифрований контейнер;
- filesystem shim Layton уже має спеціальну підтримку великих `data.unity3d`/resource-файлів;
- AssetManager і звичайні Android data paths уже емулюються.

Потрібно адаптувати:

- `check_data`, бо він жорстко вимагає Layton `globalgamemanagers` і `level0`;
- package/data paths для `ru.appscraft.durak`;
- завантаження `libsqlite3.so`;
- шлях до бази SimpleSQL;
- PlayerPrefs hooks із новими RVA.

### Lifecycle

Загальна послідовність підходить:

```text
JNI_OnLoad
→ initJni
→ nativeRecreateGfxState
→ surface changed
→ resume/focus
→ setRunning
→ nativeRender loop
```

Але сигнатури та адреси змінилися. Особливо треба визначити коректне значення третього `String` аргументу `initJni`.

## Що можна заглушити для offline

Можна взагалі не завантажувати:

- Adjust `libsigner.so`;
- Sentry;
- AppLovin crash reporter;
- рекламні native SDK;
- DataStore counter, якщо його не викликає core-path.

На рівні managed startup є важливі автоматичні ініціалізатори:

- Appodeal `UnityMainThreadDispatcher.SetContext`;
- Unity IAP/Codeless Purchasing;
- Unity Services Core;
- Unity Services Analytics.

Тому недостатньо просто видалити DEX: IL2CPP-код усе одно спробує викликати Android plugin bridge. Найкраще заглушати високорівневий Appodeal/IAP/Analytics bridge — повертати “SDK unavailable” або завершений callback. Емулювати сотні Java-класів рекламних мереж не потрібно.

Для першого меню це має бути достатньо. Для повної offline-гри треба окремо перевірити, чи внутрішня економіка не очікує rewarded ads або billing callback. Статичний аналіз не доводить, які саме виклики стоять на boot path.

## Потенційні блокери

1. **Жорсткі адреси патчів.** Memory allocator, GC, clock, Choreographer і JavaVM globals у Layton прив’язані до іншого binary build.

2. **IL2CPP metadata v39.** Не всі готові IL2CPP-інструменти коректно підтримують цю версію, тому частину адрес може знадобитися відновлювати вручну.

3. **GC і потоки.** Layton вимикає Boehm GC через несумісність signal-based stop-the-world із Horizon. Якщо Durak швидко накопичує managed allocations, повністю вимкнений GC може привести до витоку пам’яті.

4. **Unity allocator region patch.** Layton містить 18 version-specific instruction patches для роботи в 4 GB пам’яті Switch. Для Durak таблицю треба перевідновити.

5. **Асинхронні SDK boot gates.** Неправильна заглушка IAP/Appodeal/Unity Services може залишити `Task` або coroutine в нескінченному очікуванні.

6. **SQLite.** На відміну від реклами, його не можна просто вимкнути.

## Підсумкова оцінка

1. **Наскільки підходить база:** приблизно **7/10 як архітектура**, але лише **3/10 як drop-in wrapper**.

2. **Без змін можна перевикористати:** ELF/RELA loader, більшість libc/pthread shims, generic JNI infrastructure, NWindow/EGL, HID polling, virtual cursor, OpenSL/SDL backend і загальну lifecycle-схему.

3. **Доведеться адаптувати:** усі Unity/IL2CPP RVA, JNI native signatures, lifecycle, memory-region/clock/GC/Choreographer patches, asset checks, Input/PlayerPrefs hooks та FMOD selection.

4. **Доведеться додати:** три базові libc/math symbols, три SQLite symbols, завантаження `libsqlite3.so`, підтримку його alignment і цільові offline-заглушки Appodeal/IAP/Analytics.

5. **Найбільший ризик:** не реклама, а відновлення внутрішніх version-specific патчів `libunity.so`. Помилка там проявлятиметься як ранній crash, чорний екран або зависання під час першого scene load.

6. **До першого меню:** найкращий випадок — **8–12 повних робочих днів**; реалістично — **15–30 людино-днів**, тобто приблизно **3–6 тижнів** для розробника з ARM64/IL2CPP досвідом і постійним доступом до прошитого Switch для логів. Audio, збереження, стабільний GC і повне керування збільшать обсяг після першого меню.

Отже, брати `laytonbmr_nx` за базу варто: він знімає більшу частину низькорівневої роботи. Але адаптація Durak усе одно буде окремим reverse-engineering портом, а не заміною кількох назв файлів. Нічого у workspace я не змінював і wrapper не реалізовував.

> Продовжуємо тільки аналіз. Нічого не реалізовуй і не змінюй у проєкті.
>
> Мета — зрозуміти, наскільки складно буде відновити всі потрібні для Durak 25.0 адреси, RVA, entry points і patch points, які зараз жорстко прописані в laytonbmr\_nx.
>
> Проаналізуй:
>
> - які з потрібних адрес можна знайти автоматично через exports, symbols, strings, RegisterNatives, сигнатури або pattern matching;
> - які можна знайти напівавтоматично через Ghidra/IDA-подібний аналіз;
> - які доведеться шукати вручну reverse engineering’ом;
> - наскільки стабільно можна зіставити функції laytonbmr\_nx з Durak;
> - які саме точки є критичними для першого запуску і першого меню;
> - чи можна зробити скрипт/інструмент, який автоматично знаходить більшість цих адрес у libunity.so/libil2cpp.so Durak.
>
> Наприкінці дай дуже конкретно:
>
> 1. Скільки ключових RVA/patch points потрібно відновити.
> 2. Скільки з них реально знайти автоматично.
> 3. Скільки потребують ручного reverse engineering.
> 4. Які 5–10 точок є найскладнішими.
> 5. Чи виглядає це як задача, яку Codex зможе переважно виконати сам, чи тут знадобиться багато ручної роботи з мого боку.
> 6. Оціни складність саме цього етапу для full-stack розробника без досвіду ARM64/IL2CPP.
>
> Не пиши wrapper і не починай реалізацію.

<details><summary>4 previous messages</summary>

> Зосереджуся лише на карті адрес і методах їх відновлення. Спочатку інвентаризую всі жорстко задані RVA/інструкційні патчі в `laytonbmr_nx`, а потім перевірю на Durak, які з них уже можна однозначно витягнути з ELF/`RegisterNatives`/IL2CPP exports без ручного дизасемблювання. Нічого у проєкті не змінюватиму.
>
> <details><summary>Ran 10 commands, searched the web</summary>
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n '^#define .*?(OFF_|RVA|SITE|GLOBAL|_W[01]|_FROM|_TO|PATCH)|load_virtbase \+ 0x|\(b \+ 0x|patch_jump\(il2cpp_base \+ 0x' source --glob '*.{c,h}'`
>
> - Ran `sed -n '1,100p' source/region_patch.h; rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n '^#define .*0x|\+ 0x[0-9A-Fa-f]+|patch_code|patch_jump|UNITY_RESOLVE' source/main.c source/unity_input_hook.c source/unity_entrypoints.h source/region_patch.h | sed -n '1,320p'`
>
> - Ran `rg='/Applications/ChatGPT.app/Contents/Resources/rg'; "$rg" -n 'OFF_fmod|OFF_native|OFF_JNI|OFF_Time|OFF_ANDROID' source --glob '*.{c,h}'`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libunity.so')
> with p.open('rb') as f:
>  e=ELFFile(f)
>  loads=[s for s in e.iter_segments() if s['p_type']=='PT_LOAD']
>  def va_bytes(va,n=256):
>   for s in loads:
>    if s['p_vaddr'] <= va < s['p_vaddr']+s['p_filesz']:
>     off=s['p_offset']+(va-s['p_vaddr']); f.seek(off); return f.read(n)
>   return b''
>  def cstr(va):
>   b=va_bytes(va,256); z=b.find(b'\0');
>   if z<0:return None
>   try:s=b[:z].decode('ascii')
>   except:return None
>   return s if s and all(32<=ord(x)<127 for x in s) else None
>  def executable(va):
>   return any(s['p_vaddr']<=va<s['p_vaddr']+s['p_memsz'] and (s['p_flags']&1) for s in loads)
>  rels={}
>  for sn in ('.rela.dyn','.rela.plt'):
>   sec=e.get_section_by_name(sn)
>   for r in sec.iter_relocations():
>    if r['r_info_type']==1027: rels[r['r_offset']]=r['r_addend'] # R_AARCH64_RELATIVE
>  cand=[]
>  for a in sorted(rels):
>   if a+8 in rels and a+16 in rels:
>    n,s,fn=cstr(rels[a]),cstr(rels[a+8]),rels[a+16]
>    if n and s and s.startswith('(') and executable(fn): cand.append((a,n,s,fn))
>  # group contiguous
>  groups=[]
>  for x in cand:
>   if not groups or x[0]!=groups[-1][-1][0]+24:groups.append([x])
>   else:groups[-1].append(x)
>  groups=[g for g in groups if len(g)>=2]
>  print('groups',len(groups),'entries',sum(map(len,groups)))
>  for g in groups:
>   print(f'\nTABLE {g[0][0]:#x} n={len(g)}')
>   for a,n,s,fn in g: print(f'{n:45} {s:55} -> {fn:#x}')
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from elftools.elf.elffile import ELFFile
> from pathlib import Path
> for name in ('libunity.so','libil2cpp.so','libmain.so'):
>  with (Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')/name).open('rb') as f:
>   ds=ELFFile(f).get_section_by_name('.dynsym')
>   print(name)
>   for q in ('JNI_OnLoad','il2cpp_string_new','il2cpp_gc_set_mode','il2cpp_gc_disable'):
>    for s in ds.iter_symbols():
>     if s.name==q: print(q,hex(s['st_value']),s['st_size']); break
> PY`
>
> Searched the web for `site:github.com/SamboyCoding/Cpp2IL metadata version 39 Unity 6000.4 ...`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
> for name,va,n in [('libil2cpp.so',0xc0d5ec,0x80),('libunity.so',0xe86f0c,0x100)]:
>  p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')/name
>  with p.open('rb') as f:
>   e=ELFFile(f)
>   for s in e.iter_segments():
>    if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']:
>     f.seek(s['p_offset']+va-s['p_vaddr']); code=f.read(n); break
>  md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=False
>  print('\n',name,hex(va))
>  for i in md.disasm(code,va): print(f'{i.address:08x}: {i.mnemonic:8} {i.op_str}')
> PY`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" -m pip install --quiet --target /tmp/durak-analysis-py capstone`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
> for name,va,n in [('libil2cpp.so',0xc0d5ec,0x80),('libunity.so',0xe86f0c,0x100)]:
>  p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a')/name
>  with p.open('rb') as f:
>   e=ELFFile(f)
>   code=b''
>   for s in e.iter_segments():
>    if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']:
>     f.seek(s['p_offset']+va-s['p_vaddr']); code=f.read(n); break
>  md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
>  print('\n',name,hex(va))
>  for i in md.disasm(code,va): print(f'{i.address:08x}: {i.mnemonic:8} {i.op_str}')
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
> p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so'); va=0xc0c9b0; n=0x80
> with p.open('rb') as f:
>  e=ELFFile(f)
>  for s in e.iter_segments():
>   if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']:
>    f.seek(s['p_offset']+va-s['p_vaddr']); code=f.read(n); break
> for i in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(code,va): print(f'{i.address:08x}: {i.mnemonic:8} {i.op_str}')
> PY`
>
> - Ran `PY='/Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'; "$PY" - <<'PY'
> from pathlib import Path
> b=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libil2cpp.so').read_bytes()
> for q in [b'UnityEngine.Input::get_touchCount',b'UnityEngine.Input::GetTouch',b'UnityEngine.PlayerPrefs::SetString',b'UnityEngine.PlayerPrefs::Save',b'TimeManager::Update',b'ChoreographerBase',b'GetAndroidAudioOutputType',b'FMOD::System::setOutput']:
>  i=b.find(q); print(q.decode(),hex(i) if i>=0 else -1)
> PY`
>
> </details>
>
> Фактична перевірка Durak підтвердила, що найважливіший клас адрес відновлюється дуже добре: relocation-based сканер без символів знайшов 7 JNI-таблиць і 69 native methods. Зокрема, всі 37 UnityPlayer lifecycle/native callbacks та 3 FMOD methods уже мають однозначні RVA в `libunity.so`; це не потребує ручної роботи в Ghidra.
>
> <details><summary>Explored a file, ran 3 commands</summary>
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> import re,struct
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> # parse region original words
> h=Path('/tmp/layton-ref.YmMVGm/source/region_patch.h').read_text()
> rows=[(int(a,16),int(b,16),int(c,16)) for a,b,c in re.findall(r'\{0x([0-9a-f]+),\s*0x([0-9a-f]+),\s*0x([0-9a-f]+)\}',h,re.I)]
> p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libunity.so')
> with p.open('rb') as f:
>  e=ELFFile(f); text=e.get_section_by_name('.text'); data=text.data(); va=text['sh_addr']
>  print('.text',hex(va),hex(text['sh_size']))
>  seen=[]
>  for _,w,_ in rows:
>   if w in seen:continue
>   seen.append(w); pat=struct.pack('<I',w); poss=[va+i for i in range(0,len(data)-3,4) if data[i:i+4]==pat]
>   print(hex(w),len(poss),' '.join(hex(x) for x in poss[:30]))
> PY`
>
> <details><summary>Explored a file</summary>
>
> - Read `./source/main.c`
>
> </details>
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
> p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libunity.so')
> with p.open('rb') as f:
>  e=ELFFile(f); sec=e.get_section_by_name('.text'); data=sec.data(); va=sec['sh_addr']
> md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); hits=[]
> for i in md.disasm(data,va):
>  if '#0x160]' in i.op_str or '#0x168]' in i.op_str or '#0x1a8]' in i.op_str:
>   hits.append((i.address,i.mnemonic,i.op_str))
> print('hits',len(hits))
> for x in hits[:500]: print(f'{x[0]:08x}: {x[1]:8} {x[2]}')
> PY`
>
> - Ran `PYTHONPATH=/tmp/durak-analysis-py /Users/oleksandrbazavliak/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 - <<'PY'
> from pathlib import Path
> from elftools.elf.elffile import ELFFile
> from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
> p=Path('/tmp/durak25.RMJCfl/arm64/lib/arm64-v8a/libunity.so')
> with p.open('rb') as f:
>  e=ELFFile(f); sec=e.get_section_by_name('.text'); data=sec.data(); va=sec['sh_addr']
> ins=list(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(data,va))
> for k in range(len(ins)):
>  win=ins[k:k+14]; s='; '.join(i.mnemonic+' '+i.op_str for i in win)
>  if '#0x160]' in s and '#0x168]' in s and '#0x1a8]' in s and '[sp,' not in s:
>   print('\nCAND',hex(ins[k].address))
>   for i in win: print(f'{i.address:08x}: {i.mnemonic:8} {i.op_str}')
> PY`
>
> </details>
</details>

Короткий висновок: відновлення адрес значно легше, ніж здавалося. Основна маса RVA витягується структурно, без ручного пошуку в Ghidra. Найважчими залишаються 4–5 внутрішніх точок Unity, пов’язаних із часом, vsync і FMOD.

Я рахую кожен RVA окремо; 18 allocator patch sites — як 18 точок. Не рахую контрольні instruction words і три offsets полів `TimeManager`. Специфічні для Layton payment/DLC/language patches виключаю — переносити їх у Durak не потрібно.

## Що вже вдалося знайти автоматично

### Unity RegisterNatives

У `libunity.so` Durak relocation-based сканування знайшло:

- 7 таблиць `RegisterNatives`;
- 69 native methods загалом;
- основну UnityPlayer-таблицю на 37 методів;
- FMOD-таблицю на 3 методи;
- ARCore, Camera, HFP, accessibility та ReflectionHelper tables.

Для цього не потрібні debug symbols: кожен запис таблиці має структуру:

```text
pointer to method name
pointer to JNI signature
pointer to native function
```

Усі три покажчики мають `R_AARCH64_RELATIVE` relocations, тому таблиці визначаються майже безпомилково.

Ключові RVA Durak, уже отримані цим способом:

| Функція | RVA Durak |
|---|---:|
| `JNI_OnLoad` | `0xE86F0C` — через export |
| `initJni(Context,int,String)` | `0xE85C60` |
| `nativeDone` | `0xE85CE4` |
| `nativePause` | `0xE85DC4` |
| `nativeResume` | `0xE85E28` |
| `nativeApplicationUnload` | `0xE85E88` |
| `nativeFocusChanged` | `0xE85ED8` |
| `nativeRecreateGfxState` | `0xE85F3C` |
| `nativeSendSurfaceChangedEvent` | `0xE85FA4` |
| `nativeRender` | `0xE861DC` |
| `nativeInjectEvent(InputEvent,int)` | `0xE8623C` |
| `nativeUnityPlayerSetRunning` | `0xE86DB0` |
| `fmodGetInfo` | `0x108F264` |
| `fmodProcess` | `0x108F32C` |
| `fmodProcessMicData` | `0x108F3B8` |

Це надійні результати: ім’я, JNI-сигнатура й адреса функції пов’язані relocation table, а сигнатури додатково звіряються з DEX.

Саме таким шляхом автор Layton відновлював свої Unity entry points. [unity_entrypoints.h](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/unity_entrypoints.h)

### IL2CPP JavaVM globals

`libil2cpp.so` Durak експортує `JNI_OnLoad` на `0xC0D5EC`. Його функція коротка й машинно розбирається:

- JavaVM cache: `0x1DE50F8`;
- JNI handler slot: `0x1DE50D8`;
- JNI handler function: `0xC0D630`.

Тобто три адреси, які Layton прописує вручну, для Durak можна визначати автоматично аналізом `ADRP/ADD/STR/ADR` усередині exported `JNI_OnLoad`.

В ідеалі wrapper взагалі мав би викликати справжній IL2CPP `JNI_OnLoad`. Але якщо зберігати Layton-підхід із прямим записом globals, ці три точки теж не потребують Ghidra.

### 18 memory-region patch sites

Це несподівано добре переноситься між Unity `6000.0.58f2` і `6000.4.0b6`.

У Durak майже всі оригінальні ARM64 instruction words із `region_patch.h` збереглися byte-for-byte. Вони утворюють чіткий кластер приблизно:

```text
0xFA116C … 0xFA8108
```

Наприклад:

- перша пара — біля `0xFA116C/0xFA117C`;
- TLS allocator — `0xFA19F8`;
- основний блок VirtualAllocator — `0xFA7D90…0xFA8108`.

Окремі instruction words зустрічаються в інших місцях, але лише цей кластер має повну послідовність усіх 18 операцій. Отже, таблицю можна побудувати автоматично з перевіркою:

- instruction class;
- immediate value;
- порядок точок;
- відстані між сусідніми функціями;
- наявність усіх 18 елементів або відмова від патча.

Це відповідає тому, як таблиця описана в [region_patch.h](https://github.com/NaGaa95/laytonbmr_nx/blob/5763d239f03e57447832bcb1450a3ac1099846c7/source/region_patch.h).

## Що знаходиться через IL2CPP metadata

У `laytonbmr_nx` жорстко прописано 16 IL2CPP methods:

### Input — 6

- `Input.get_touchCount`
- `Input.get_mousePosition`
- `Input.GetMouseButton`
- `Input.GetMouseButtonDown`
- `Input.GetMouseButtonUp`
- `Input.GetTouch`

### PlayerPrefs — 10

- `SetString`
- `SetInt`
- `SetFloat`
- два overloads `GetString`
- `GetInt`
- `GetFloat`
- `HasKey`
- `DeleteKey`
- `Save`

Вони повинні знаходитися автоматично через:

```text
global-metadata.dat
→ image/assembly
→ namespace + class + method
→ signature/overload
→ method index
→ code registration
→ method pointer RVA
```

Проблема не в пошуку конкретних 16 методів, а в підтримці metadata version 39, яку використовує Durak. Якщо готовий IL2CPP parser її не розуміє, треба адаптувати layout структур metadata/code registration.

Після цього всі 16 адрес знаходяться детерміновано. Ghidra потрібна лише для перевірки ABI:

- чи є прихований `MethodInfo*`;
- як повертається `UnityEngine.Touch`;
- чи не є метод generic/shared thunk;
- чи можна безпечно перезаписати перші 16 байтів.

Отже, це напівавтоматична робота на початку, але повністю автоматична після створення metadata extractor.

## Що потребує Ghidra/IDA-подібного аналізу

### `ChoreographerBase::Get`

У Layton патч стоїть на внутрішній функції, яка повертає singleton Choreographer. Вона не експортується.

Її можна звузити автоматично:

1. знайти import `AChoreographer_getInstance`;
2. знайти GOT/PLT references;
3. побудувати callers;
4. знайти wrapper/singleton accessor;
5. звірити callers з `nativeRender`/frame pacing path.

Остаточний вибір функції треба підтвердити control-flow аналізом. Це типова напівавтоматична точка.

### `TimeManager::Update`

Це вже складніше. Потрібно підтвердити:

- початок функції;
- адресу entry;
- адресу body після раннього `return`;
- поля `frameCount`, aux counter і pause flag;
- передачу `double newTime` у `d0`;
- що hook не пропускає важливу частину прологу.

Пошук можливий через pattern matching і зіставлення із symbolicated Unity Player тієї ж версії, але без symbols потрібна ручна перевірка дизасемблювання.

### Android vsync counter

Глобальна змінна не має імені чи relocation зі зрозумілою назвою. Треба:

- знайти `WaitForLastPresentation`;
- відстежити цикл `counter < target`;
- визначити адресу глобального counter;
- перевірити, чи структура не змінилася в Unity 6000.4.

Це одна з найбільш ручних точок.

### FMOD `setOutput` patch

Потрібно знайти місце, де Unity передає FMOD output type, і встановити правильний enum OpenSL.

Навіть якщо call site знаходиться pattern matching’ом, треба підтвердити:

- який register містить output type;
- яке значення означає AudioTrack/AAudio/OpenSL саме в цій версії FMOD;
- чи доступний OpenSL path у цьому build.

Для першого меню ця точка не потрібна — можна починати без audio.

## Наскільки стабільне зіставлення Layton → Durak

| Категорія | Стабільність |
|---|---|
| ELF exports | дуже висока |
| `RegisterNatives` tables | дуже висока |
| JNI signatures + DEX | дуже висока |
| IL2CPP methods через metadata | висока після підтримки v39 |
| Region allocator instruction patterns | висока; фактично підтверджена |
| IL2CPP `JNI_OnLoad` globals | висока |
| Choreographer call graph | середня-висока |
| `TimeManager::Update` | середня |
| vsync global | низька-середня |
| FMOD output patch | середня-низька |
| Просте перенесення старого RVA delta | неприйнятне |

Простого постійного зміщення між binaries немає. Функції можна зіставляти семантично, але не за формулою `Durak RVA = Layton RVA + delta`.

## Критичні точки до першого меню

### Просто побачити меню — 33 точки

- 8 Unity boot/lifecycle entry points;
- 3 IL2CPP JavaVM/handler addresses;
- 18 allocator-region sites;
- 2 точки `TimeManager::Update`;
- 1 Choreographer patch;
- 1 Android vsync counter.

### Меню з touchscreen/стіками — 39 точок

Попередні 33 плюс 6 `UnityEngine.Input` methods.

### Меню зі стабільними PlayerPrefs — 49 точок

Попередні 39 плюс 10 `PlayerPrefs` methods.

Audio patch не критичний. Shutdown-only methods також не потрібні для першого кадру.

## Чи можна автоматизувати більшість

Так. Один аналізатор міг би приймати:

```text
libunity.so
libil2cpp.so
global-metadata.dat
classes*.dex
```

і генерувати звіт із:

- exports;
- `RegisterNatives` tables;
- JNI signatures;
- Unity lifecycle RVA;
- FMOD JNI RVA;
- IL2CPP JNI globals;
- Input/PlayerPrefs RVA;
- allocator patch table;
- instruction fingerprints;
- confidence score та список неоднозначних точок.

Практично це не має бути Ghidra plugin. ELF parser + ARM64 decoder + metadata parser достатні для приблизно 90% адрес. Headless Ghidra корисний для call graph і фінальної верифікації 4–5 складних функцій.

## Конкретні числа

### 1. Скільки ключових точок потрібно відновити

Повна заміна generic hardcoded inventory `laytonbmr_nx`:

- **77 RVA/patch points**.

Розклад:

| Група | Кількість |
|---|---:|
| Unity natives + `JNI_OnLoad` | 32 |
| FMOD registered natives | 3 |
| Region allocator patches | 18 |
| IL2CPP JavaVM/handler | 3 |
| Input | 6 |
| PlayerPrefs | 10 |
| `TimeManager` entry/body | 2 |
| Vsync counter | 1 |
| Choreographer | 1 |
| FMOD output patch | 1 |
| **Разом** | **77** |

Durak має ще 6 нових Unity native entries порівняно з Layton, але вони знаходяться тією самою автоматичною процедурою і не всі потрібні wrapper’у.

### 2. Скільки реально знайти автоматично

- **56 уже можна знайти повністю механічно**: exports, `RegisterNatives`, `JNI_OnLoad` analysis, region patterns.
- Ще **16 автоматизуються після підтримки IL2CPP metadata v39**.
- Разом реалістично автоматизувати **72 із 77**.

### 3. Скільки потребують ручного reverse engineering

- **1 напівавтоматична:** Choreographer accessor.
- **4 ручні/семантичні:** `TimeManager` entry, `TimeManager` body, vsync counter, FMOD setOutput site.

Для першого меню без audio — фактично **3 складні ручні точки** плюс Choreographer.

Можливі додаткові Durak-specific Appodeal/IAP boot gates сюди не включені: їхня наявність на критичному startup path поки не доведена. Якщо вони є, це орієнтовно ще 1–5 game-specific methods.

### 4. Найскладніші точки

1. `TimeManager::Update` entry.
2. Коректна адреса `TimeManager::Update` body.
3. Layout полів `TimeManager`.
4. Android presentation/vsync counter.
5. `ChoreographerBase::Get`.
6. FMOD `setOutput` call site.
7. Правильний FMOD OpenSL enum.
8. IL2CPP metadata/code registration format v39.
9. ABI повернення `UnityEngine.Touch`.
10. Durak-specific async SDK boot gates, якщо вони виявляться.

### 5. Чи зможе Codex переважно виконати цей етап

Так, **більшість статичної роботи Codex може виконати самостійно**:

- ELF/relocation parsing;
- RegisterNatives extraction;
- ARM64 pattern scanning;
- IL2CPP metadata parsing;
- call-graph narrowing;
- генерація таблиці RVA та confidence checks;
- аналіз дизасемблювання складних кандидатів.

Від вас не повинно знадобитися багато ручної роботи в Ghidra. Основна участь з вашого боку — запуск діагностичної збірки на реальному Switch і передача логів/crash addresses. Без hardware validation неможливо остаточно підтвердити TimeManager, vsync, GC і allocator behavior.

### 6. Складність для full-stack розробника без ARM64/IL2CPP

Самостійно: **8.5/10**.

Найскладніше — не читання окремих ARM64 інструкцій, а правильне розуміння ABI, hidden arguments, indirect calls, IL2CPP registration і того, чому Unity зависає між першим кадром та завантаженням сцени.

З автоматичним extractor’ом і готовими кандидатами: приблизно **5–6/10**. Тоді робота переважно зводиться до перевірки кількох функцій і hardware iteration.

Реалістична оцінка саме цього етапу:

- досвідчений ARM64/Unity reverse engineer: **4–8 робочих днів**;
- full-stack розробник без такого досвіду: **3–6 тижнів**;
- Codex + доступ до APK і ваші тести на Switch: орієнтовно **1–2 тижні аналізу та ітерацій**, якщо metadata v39 не має радикально нового registration layout.

Отже, пошук усіх 77 точок не є 77 окремими ручними задачами. Реально це приблизно 72 структурно відновлювані адреси та 4–5 функцій, де потрібен справжній reverse engineering.
