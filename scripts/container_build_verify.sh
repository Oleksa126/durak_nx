#!/usr/bin/env bash
set -euo pipefail
git config --global --add safe.directory /workspace || true
source /opt/devkitpro/switchvars.sh
make clean
make
gcc -O2 -Wall -Wextra -Iinclude tests/test_static_catalog_native.c -lpthread -o /tmp/test_static_catalog
/tmp/test_static_catalog
gcc -O2 -Wall -Wextra -Iinclude tests/test_static_catalog_patch_native.c -o /tmp/test_static_catalog_patch
/tmp/test_static_catalog_patch
gcc -O2 -Iinclude tests/test_target_verify_native.c source/durak_target_verify.c source/sha256.c -o /tmp/test_target_verify
/tmp/test_target_verify

gcc -O2 -Iinclude tests/test_sha256_fast_native.c source/sha256.c -o /tmp/test_sha256_fast_native
/tmp/test_sha256_fast_native
gcc -O2 -Iinclude tests/test_loader_linker_native.c tests/boot_screen_input_stub.c source/so_util.c source/durak_pre_entry_audit.c source/durak_target_verify.c source/fail_stop_thunks.c source/sha256.c source/util.c source/error.c source/region_patch.c source/frame_pacer.c source/unity_input_hook.c -lpthread -lm -o /tmp/test_loader_linker_native
/tmp/test_loader_linker_native
gcc -O2 -Iinclude tests/test_input_menu_native.c -lm -o /tmp/test_input_menu_native
/tmp/test_input_menu_native
gcc -O2 -DBOOT_SCREEN_NATIVE_TEST -Itests/boot_screen_mocks -Iinclude -Ibuild-obj tests/test_boot_screen_native.c tests/loading_art_native.S source/boot_screen.c -lm -o /tmp/test_boot_screen_native
/tmp/test_boot_screen_native
/tmp/test_boot_screen_native create
/tmp/test_boot_screen_native linear
/tmp/test_boot_screen_native decode
/tmp/test_boot_screen_native thread
/tmp/test_boot_screen_native thread-create
/tmp/test_boot_screen_native layer
/tmp/test_boot_screen_native default-create
/tmp/test_boot_screen_native default-linear
/tmp/test_boot_screen_native private-create
/tmp/test_boot_screen_native private-linear
gcc -O2 -Wall -Wextra -Itests/loading_layer_mocks -Iinclude tests/test_loading_layer_native.c source/loading_layer.c -o /tmp/test_loading_layer_native
/tmp/test_loading_layer_native
gcc -O2 -Wall -Wextra -Itests/loading_layer_mocks -Iinclude tests/test_default_display_native.c source/default_display.c -o /tmp/test_default_display_native
/tmp/test_default_display_native
gcc -O2 -Wall -Wextra -DBOOT_SCREEN_NATIVE_TEST -Itests/boot_screen_mocks -Iinclude -Ibuild-obj tests/test_loading_async_native.c tests/loading_art_native.S source/boot_screen.c -lpthread -lm -o /tmp/test_loading_async_native
/tmp/test_loading_async_native

gcc -O2 -Wall -Wextra -DEGL_NO_X11 -DLOADING_GL_NATIVE_TEST -Itests/boot_screen_mocks -Iinclude -Ibuild-obj -I/opt/devkitpro/portlibs/switch/include tests/test_loading_async_native.c tests/loading_gl_stubs.c tests/loading_art_native.S source/boot_screen.c -lpthread -lm -o /tmp/test_loading_gl_native
/tmp/test_loading_gl_native
gcc -O2 -Itests/egl_loading_mocks -Iinclude tests/test_egl_loading_native.c source/egl_loading.c -o /tmp/test_egl_loading_native
/tmp/test_egl_loading_native
gcc -O2 -Iinclude tests/test_log_batch_native.c source/util.c -Wl,--wrap=fsync -Wl,--wrap=clock_gettime -lpthread -o /tmp/test_log_batch_native
/tmp/test_log_batch_native

gcc -O2 -Wall -Wextra -Iinclude tests/test_boot_measure_native.c source/util.c -Wl,--wrap=clock_gettime -lpthread -o /tmp/test_boot_measure_native
/tmp/test_boot_measure_native

gcc -O2 -Wall -Wextra -Iinclude tests/test_read_ahead_native.c source/read_ahead.c -Wl,--wrap=read -Wl,--wrap=lseek -lpthread -o /tmp/test_read_ahead_native
/tmp/test_read_ahead_native

gcc -O2 -Wall -Wextra -Iinclude tests/test_asset_stat_native.c source/asset_stat.c source/read_ahead.c -Wl,--wrap=stat -lpthread -o /tmp/test_asset_stat_native
/tmp/test_asset_stat_native

gcc -O2 -Wall -Wextra -Iinclude tests/test_sqlite_probe_cache_native.c source/sqlite_probe_cache.c -lpthread -o /tmp/test_sqlite_probe_cache_native
/tmp/test_sqlite_probe_cache_native
python3 -m unittest tests.test_single_game_stat
gcc -O2 -Wall -Wextra -Iinclude tests/test_sqlite_exports_native.c source/sqlite_exports.c -lpthread -o /tmp/test_sqlite_exports_native
/tmp/test_sqlite_exports_native

gcc -O2 -Wall -Wextra -Iinclude tests/test_case_probe_cleanup_native.c source/case_probe_cleanup.c -Wl,--wrap=unlink -lpthread -o /tmp/test_case_probe_cleanup_native
/tmp/test_case_probe_cleanup_native
gcc -O2 -Wall -Wextra -fPIC -shared -Iinclude tests/inventory_native_stub.c source/cosmetics_inventory.c source/region_patch.c -o build-obj/test_inventory_native.so
