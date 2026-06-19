/*
 * RPC fuzzer for p11-kit
 *
 * OSV-2023-205: Global-buffer-overflow READ 8 in base_C_MessageSignFinal
 * The function base_C_MessageSignFinal calls funcs->C_MessageSignFinal()
 * without checking if the underlying module supports PKCS#11 v3.0.
 * When the mock module (v2.x) is used, the function pointer is beyond
 * the bounds of the CK_FUNCTION_LIST structure, causing global OOB READ.
 * OSS-Fuzz issue: 57202
 * Fix commit: d7c31884
 *
 * NOTE: This fuzzer requires p11-kit's internal headers and mock module.
 * It's built as part of the p11-kit build system via meson/make.
 * For standalone use, we link against the built p11-kit libraries.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Forward declaration - we'll call p11_rpc_server_handle through the library */
#include "config.h"

#include "library.h"
#include "mock.h"
#include "virtual.h"
#include "p11-kit/rpc.h"

static p11_virtual base;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    p11_buffer buffer;

    mock_module_init();
    p11_library_init();

    p11_buffer_init(&buffer, 0);

    p11_virtual_init(&base, &p11_virtual_base, &mock_module_no_slots, NULL);
    base.funcs.C_Initialize(&base.funcs, NULL);

    p11_buffer_add(&buffer, data, size);

    p11_rpc_server_handle(&base.funcs, &buffer, &buffer);

    p11_buffer_uninit(&buffer);
    mock_module_reset();
    p11_library_uninit();

    return 0;
}
