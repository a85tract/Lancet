/*
 * openh264 decoder fuzzer - based on google/oss-fuzz projects/openh264/decoder_fuzzer.cpp
 * Feeds raw H.264 NAL data to the openh264 decoder.
 */
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "codec_api.h"

static ISVCDecoder *pDecoder = nullptr;

static void initialize() {
    if (pDecoder != nullptr) return;

    WelsCreateDecoder(&pDecoder);

    SDecodingParam sDecParam;
    memset(&sDecParam, 0, sizeof(SDecodingParam));
    sDecParam.sVideoProperty.eVideoBsType = VIDEO_BITSTREAM_AVC;
    sDecParam.eEcActiveIdc = ERROR_CON_SLICE_COPY;

    pDecoder->Initialize(&sDecParam);

    // Disable logging
    int32_t iTraceLevel = WELS_LOG_QUIET;
    pDecoder->SetOption(DECODER_OPTION_TRACE_LEVEL, &iTraceLevel);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    initialize();

    // Scan for NAL start codes and decode each NAL unit
    uint8_t *pDst[3] = {0};
    SBufferInfo sDstBufInfo;
    memset(&sDstBufInfo, 0, sizeof(SBufferInfo));

    pDecoder->DecodeFrameNoDelay(data, (int)size, pDst, &sDstBufInfo);

    return 0;
}
