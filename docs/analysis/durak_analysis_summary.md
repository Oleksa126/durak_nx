# Звіт Milestone M1: Verified Target and Evidence

Цей звіт сформовано інструментом `durak_analyzer.py` (fail-closed).
Кожна адреса отримана через структурні докази (ELF relocations, IL2CPP metadata v39, ARM64 disassembly).

## 1. Ідентифікація та цілісність бінарних файлів

| Файл | Розмір (bytes) | GNU Build ID | SHA-256 |
|---|---:|---|---|
| `libmain.so` | 6696 | `c5498ab8c791f1473a54c79a9d3c5b738ff6d941` | `c11373dffa1bab42...` |
| `libunity.so` | 21388304 | `bcc661ea2046416d` | `292f89210151ba00...` |
| `libil2cpp.so` | 31256704 | `d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0` | `7bc9c2e7e20c741a...` |
| `libsqlite3.so` | 1797248 | `99495662cefa74605573c8dc36a53cb1f842764d` | `6df7a75d31c417ca...` |

- **global-metadata.dat**: розмір 7639464 bytes, версія 39, magic `0xfab11baf`, SHA-256 `1e31859eca996941...`.

## 2. Unity RegisterNatives та Lifecycle RVA (`libunity.so`)

Доведено прив'язку таблиць нативних методів до конкретних Java-класів через трасування call-sites `RegisterNatives` у `JNI_OnLoad`:

| Метод | Сигнатура | Java Class | Call-Site RVA | RVA Durak 25.0 |
|---|---|---|---:|---:|
| `AndroidAudioDeviceListChanged` | `()V` | `com/unity3d/player/AudioDeviceObserver` | `0xe87344` | `0x85B7D4` |
| `AndroidAudioLoggingEnabled` | `()Z` | `com/unity3d/player/AudioDeviceObserver` | `0xe87344` | `0x85B828` |
| `JNI_OnLoad` | `(JavaVM*, void*) -> jint` | `` | `` | `0xE86F0C` |
| `JNI_OnUnload` | `(JavaVM*, void*) -> void` | `` | `` | `0xE87388` |
| `deinitHFPStatusJni` | `()V` | `com/unity3d/player/HFPStatus` | `0xe63a28` | `0xE63978` |
| `getRootNodeIds` | `()[I` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE89120` |
| `hitTest` | `(FF)I` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE892D0` |
| `initCamera2Jni` | `()V` | `com/unity3d/player/Camera2Wrapper` | `0xe7cdcc` | `0xE7CD18` |
| `initHFPStatusJni` | `()V` | `com/unity3d/player/HFPStatus` | `0xe63a28` | `0xE6392C` |
| `initJni` | `(Landroid/content/Context;ILjava/lang/String;)V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE85C60` |
| `initializeARCore` | `(Landroid/app/Activity;)V` | `com/unity3d/player/GoogleARCoreApi` | `0xe5ebf4` | `0xE60D54` |
| `isNodeDismissable` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8A89C` |
| `isNodeInvokable` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8A2D8` |
| `isNodeScrollable` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8A6B0` |
| `isNodeSlider` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8A4C4` |
| `nativeApplicationUnload` | `()V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE85E88` |
| `nativeConfigurationChanged` | `(Landroid/content/res/Configuration;)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE8614C` |
| `nativeCrashNow` | `()V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86ECC` |
| `nativeDone` | `()Z` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85CE4` |
| `nativeFocusChanged` | `(Z)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85ED8` |
| `nativeFrameReady` | `(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V` | `com/unity3d/player/Camera2Wrapper` | `0xe7cdcc` | `0xE6FD28` |
| `nativeGetMainWindowIndex` | `()I` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86E74` |
| `nativeGetNoWindowMode` | `()Z` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE86E04` |
| `nativeGetSoftInputType` | `()I` | `com/unity3d/player/SoftInputProvider` | `0xe96588` | `0xE96460` |
| `nativeHidePreservedContent` | `()V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86C98` |
| `nativeInjectEvent` | `(Landroid/view/InputEvent;I)Z` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE8623C` |
| `nativeIsAutorotationOn` | `()Z` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86A18` |
| `nativeMemoryUsageChanged` | `(I)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85D70` |
| `nativeMuteMasterAudio` | `(Z)V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86A78` |
| `nativeOnApplyWindowInsets` | `(Landroid/view/WindowInsets;)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85FF8` |
| `nativeOrientationChanged` | `(II)V` | `com/unity3d/player/UnityPlayerForGameActivity` | `0xe87258` | `0xE86D50` |
| `nativePause` | `()Z` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85DC4` |
| `nativeProxyFinalize` | `(J)V` | `com/unity3d/player/ReflectionHelper` | `0x4ba6d4` | `0x4BAF24` |
| `nativeProxyInvoke` | `(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;` | `com/unity3d/player/ReflectionHelper` | `0x4ba6d4` | `0x4BAE04` |
| `nativeProxyJNIFreeGCHandle` | `(J)V` | `com/unity3d/player/ReflectionHelper` | `0x4ba6d4` | `0x4BAFD8` |
| `nativeProxyLogJNIInvokeException` | `(J)V` | `com/unity3d/player/ReflectionHelper` | `0x4ba6d4` | `0x4BAF64` |
| `nativeRecreateGfxState` | `(ILandroid/view/Surface;)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85F3C` |
| `nativeRender` | `()Z` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE861DC` |
| `nativeReportKeyboardConfigChanged` | `()V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE867AC` |
| `nativeResume` | `()V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85E28` |
| `nativeSendSurfaceChangedEvent` | `()V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE85FA4` |
| `nativeSetInputArea` | `(IIII)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE864FC` |
| `nativeSetInputSelection` | `(II)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE8668C` |
| `nativeSetInputString` | `(Ljava/lang/String;)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE865E4` |
| `nativeSetKeyboardIsVisible` | `(Z)V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE86584` |
| `nativeSetLaunchURL` | `(Ljava/lang/String;)V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86ADC` |
| `nativeSoftInputCanceled` | `()V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE866FC` |
| `nativeSoftInputClosed` | `()V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE867F4` |
| `nativeSoftInputLostFocus` | `()V` | `com/unity3d/player/UnityPlayerForActivityOrService` | `0xe8716c` | `0xE86754` |
| `nativeStatusQueryResult` | `(Ljava/lang/String;II)V` | `com/unity3d/player/UnityCoreAssetPacksStatusCallbacks` | `0xe631b8` | `0xE62F70` |
| `nativeSurfaceTextureReady` | `(Ljava/lang/Object;)V` | `com/unity3d/player/Camera2Wrapper` | `0xe7cdcc` | `0xE6FBC0` |
| `nativeUnityPlayerSetRunning` | `(Z)V` | `com/unity3d/player/UnityPlayerForGameActivity` | `0xe87258` | `0xE86DB0` |
| `nativeUnitySendMessage` | `(Ljava/lang/String;Ljava/lang/String;[B)V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE8684C` |
| `nativeUpdateOrientationLockState` | `(I)V` | `com/unity3d/player/OrientationLockListener` | `0xe61a18` | `0xE61908` |
| `nativeViewPaddingChanged` | `(IIIII)V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86CE8` |
| `onAudioVolumeChanged` | `(I)V` | `com/unity3d/player/AudioVolumeHandler` | `0xe82b3c` | `0xE82A24` |
| `onClosedCaptioningStatusChanged` | `(Z)V` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8B09C` |
| `onFontScaleChanged` | `(F)V` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8B020` |
| `onNodeDecremented` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8ACE8` |
| `onNodeDismissed` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8AEBC` |
| `onNodeFocusChanged` | `(IZ)V` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8AA88` |
| `onNodeIncremented` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8AC18` |
| `onNodeInvoked` | `(I)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8AB48` |
| `onNodeScrolled` | `(II)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8ADB8` |
| `onScreenReaderStatusChanged` | `(Z)V` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE8AF8C` |
| `pauseARCore` | `()V` | `com/unity3d/player/GoogleARCoreApi` | `0xe5ebf4` | `0xE60DB8` |
| `permissionResponseToNative` | `(JZ)V` | `com/unity3d/player/UnityPlayer` | `0xe87080` | `0xE86C14` |
| `populateNodeInfo` | `(Landroid/view/accessibility/AccessibilityNodeInfo;ILandroid/view/View;)Z` | `com/unity3d/player/UnityAccessibilityDelegate` | `0xe8b1dc` | `0xE89E4C` |
| `resumeARCore` | `()V` | `com/unity3d/player/GoogleARCoreApi` | `0xe5ebf4` | `0xE60E0C` |
| `[FMOD] fmodGetInfo` | `(I)I` | `org/fmod/FMODAudioDevice` | `0x108e8c8` | `0x108F264` |
| `[FMOD] fmodProcess` | `(Ljava/nio/ByteBuffer;)I` | `org/fmod/FMODAudioDevice` | `0x108e8c8` | `0x108F32C` |
| `[FMOD] fmodProcessMicData` | `(Ljava/nio/ByteBuffer;I)I` | `org/fmod/FMODAudioDevice` | `0x108e8c8` | `0x108F3B8` |

## 3. Memory Region Granularity Patches (256MB -> 64MB)

Усі 18 інструкцій локалізовано через **multi-instruction fingerprint matching** по всій секції `.text`:

| # | RVA | From (256MB) | To (64MB) | Опис |
|---|---:|---:|---:|---|
| 1 | `0xFA116C` | `0x12be0009` | `0x12bf8009` | MOV LocalLowLevelAllocator::ReserveMemoryBlock (256MB-1 mask hi) |
| 2 | `0xFA117C` | `0x92648d35` | `0x92669535` | LOGIMM LocalLowLevelAllocator::ReserveMemoryBlock (~low28 mask) |
| 3 | `0xFA19F8` | `0x52a20008` | `0x52a08008` | MOV TLSAllocator::ThreadInitialize (256MB const) |
| 4 | `0xFA406C` | `0x52a20009` | `0x52a08009` | MOV BucketAllocator::ctor (256MB const) |
| 5 | `0xFA60D8` | `0x52a20009` | `0x52a08009` | MOV DynamicHeapAllocator::ctor (256MB region size) |
| 6 | `0xFA65A4` | `0x12be000d` | `0x12bf800d` | MOV DynamicHeapAllocator::RequestLargeAllocMemory (256MB-1 mask hi) |
| 7 | `0xFA65D0` | `0x92648d36` | `0x92669536` | LOGIMM DynamicHeapAllocator::RequestLargeAllocMemory (~low28 mask) |
| 8 | `0xFA7D90` | `0xd35cdc33` | `0xd35ad433` | BITF VirtualAllocator::MarkMemoryBlocks (ubfx #28,#28) |
| 9 | `0xFA7D98` | `0xd35cfd15` | `0xd35afd15` | BITF VirtualAllocator::MarkMemoryBlocks (lsr #28) |
| 10 | `0xFA7E3C` | `0x52a20008` | `0x52a08008` | MOV VirtualAllocator::ReserveMemoryBlock (256MB const) |
| 11 | `0xFA806C` | `0xd35cfc28` | `0xd35afc28` | BITF VirtualAllocator::GetMemoryBlockFromPointer (lsr #28) |
| 12 | `0xFA807C` | `0x92646c28` | `0x92667428` | LOGIMM VirtualAllocator::GetMemoryBlockFromPointer (~low28 mask) |
| 13 | `0xFA8084` | `0xd35c9c2a` | `0xd35a942a` | BITF VirtualAllocator::GetMemoryBlockFromPointer (ubfx #28,#12) |
| 14 | `0xFA8098` | `0xd35cdc29` | `0xd35ad429` | BITF VirtualAllocator::GetMemoryBlockFromPointer (ubfx #28,#28) |
| 15 | `0xFA809C` | `0xb25c6feb` | `0xb25e77eb` | LOGIMM VirtualAllocator::GetMemoryBlockFromPointer (-255*gran hi) |
| 16 | `0xFA80A0` | `0xf2a2000b` | `0xf2a0800b` | MOV VirtualAllocator::GetMemoryBlockFromPointer (movk 256MB) |
| 17 | `0xFA80E4` | `0xcb0a7108` | `0xcb0a6908` | SHREG VirtualAllocator::GetMemoryBlockFromPointer (sub lsl #28) |
| 18 | `0xFA8108` | `0xd35c9c29` | `0xd35a9429` | BITF VirtualAllocator::GetBlockInfoFromPointer (ubfx #28,#12) |

## 4. IL2CPP JNI Globals (`libil2cpp.so`)

- `JNI_OnLoad` export: `0xC0D5EC`
- `JavaVM*` cache global: `0x1DE50F8`
- JNI handler slot global: `0x1DE50D8`
- JNI handler function: `0xC0D630`

## 5. IL2CPP Metadata v39: Input & PlayerPrefs з канонічними сигнатурами

### Input методи:

| Метод | Сигнатура | RID | RVA Durak 25.0 |
|---|---|---:|---:|
| `UnityEngine.Input::get_touchCount` | `System.Int32 get_touchCount()` | 46 | `0x184408C` |
| `UnityEngine.Input::get_mousePosition` | `UnityEngine.Vector3 get_mousePosition()` | 34 | `0x1843BB4` |
| `UnityEngine.Input::GetMouseButton` | `System.Boolean GetMouseButton(System.Int32 button)` | 25 | `0x18438E4` |
| `UnityEngine.Input::GetMouseButtonDown` | `System.Boolean GetMouseButtonDown(System.Int32 button)` | 26 | `0x1843920` |
| `UnityEngine.Input::GetMouseButtonUp` | `System.Boolean GetMouseButtonUp(System.Int32 button)` | 27 | `0x184395C` |
| `UnityEngine.Input::GetTouch` | `UnityEngine.Touch GetTouch(System.Int32 index)` | 28 | `0x1843998` |

### PlayerPrefs методи (роздільні перевантаження):

| Метод | Канонічна сигнатура | RID | RVA Durak 25.0 |
|---|---|---:|---:|
| `PlayerPrefs::SetInt` | `System.Void SetInt(System.String key, System.Int32 value)` | 2365 | `0x17EEB9C` |
| `PlayerPrefs::GetInt1` | `System.Int32 GetInt(System.String key)` | 2367 | `0x17EEDB0` |
| `PlayerPrefs::GetInt2` | `System.Int32 GetInt(System.String key, System.Int32 defaultValue)` | 2366 | `0x17EEBF4` |
| `PlayerPrefs::SetString` | `System.Void SetString(System.String key, System.String value)` | 2368 | `0x17EEDB8` |
| `PlayerPrefs::GetString1` | `System.String GetString(System.String key)` | 2370 | `0x17EF114` |
| `PlayerPrefs::GetString2` | `System.String GetString(System.String key, System.String defaultValue)` | 2369 | `0x17EEE10` |
| `PlayerPrefs::HasKey` | `System.Boolean HasKey(System.String key)` | 2371 | `0x17EF15C` |
| `PlayerPrefs::DeleteKey` | `System.Void DeleteKey(System.String key)` | 2372 | `0x17EF30C` |
| `PlayerPrefs::Save` | `System.Void Save()` | 2373 | `0x17EF4B0` |

### ABI Analysis & Engine Stripping Evidence:

- **PlayerPrefs code stripping**: `has_set_float = False`, `has_get_float = False`. Доказ: Unity Engine code stripping removed SetFloat and GetFloat because they are unused in game IL2CPP assemblies.
- **`UnityEngine.Touch` return ABI**: x8 (AAPCS64 value-type return buffer saved to x19), розмір структури UnityEngine.Touch (size 0x44 / 68 bytes), регістр індексу w0 (int32 touch index). Перевірено у машинному коді: True.
- **Memcpy PLT Stub Target**: `0x1af5f30` -> Symbol `memcpy`.

## 6. Engine Clock: `TimeManager::Update`

- Entry RVA: `0xBBF058`
- Body RVA: `0xBBF07C`
- Зміщення: frameCount=`+0x160 (u64)`, aux=`+0x168 (u32)`, pause=`+0x1a8 (u8)`
- Relocation slot: `0x1427200`

## 7. Невстановлені точки / Потребують Hardware Gate

- **Choreographer / Vsync**: Статус: `UNRESOLVED_REQUIRES_HARDWARE_VALIDATION`. Примітки: Choreographer and Vsync presentation hooks deferred to runtime hardware gate. No hardcoded RVAs emitted in production header.
- **FMOD setOutput**: відкладено до аудіо етапу.
