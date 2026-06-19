/*
 * OSS-Fuzz harness for OSV-2023-382
 * Bug: Use-of-uninitialized-value in PrintInitExpr from element expressions.
 * Target: wasm2wat_fuzzer (ReadBinaryIr)
 * Fix: ab05e50ec44506dc81220a21fb8f5e8d048772e0
 *
 * This version uses "wabt/" include prefix (headers in include/wabt/).
 */

#include "wabt/binary-reader-ir.h"
#include "wabt/binary-reader.h"
#include "wabt/common.h"
#include "wabt/ir.h"
#include "wabt/stream.h"
#include "wabt/wat-writer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wabt::ReadBinaryOptions options;
  wabt::Errors errors;
  wabt::Module module;
  wabt::Result result =
      wabt::ReadBinaryIr("dummy", data, size, options, &errors, &module);
  if (wabt::Succeeded(result)) {
    wabt::WriteWatOptions wat_options;
    wabt::MemoryStream stream;
    wabt::WriteWat(&stream, &module, wat_options);
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <wasm_file>\n", argv[0]);
    return 1;
  }
  FILE* f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t* buf = (uint8_t*)malloc(len);
  if (!buf) {
    fclose(f);
    return 1;
  }
  fread(buf, 1, len, f);
  fclose(f);

  int ret = LLVMFuzzerTestOneInput(buf, len);
  free(buf);
  return ret;
}
