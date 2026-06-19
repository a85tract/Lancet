/*
 * OSS-Fuzz harness for OSV-2020-1629
 * Bug: Segv on unknown address in wabt::BinaryReader::PrintError
 *      when processing reloc section with an imported table that has no name.
 * Target: wasm2wat_fuzzer (ReadBinaryIr)
 * Fix: 09ac53e41d959ce8e14e703e627327971e67f6d3
 */

#include "src/binary-reader-ir.h"
#include "src/binary-reader.h"
#include "src/common.h"
#include "src/ir.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wabt::ReadBinaryOptions options;
  wabt::Errors errors;
  wabt::Module module;
  wabt::ReadBinaryIr("dummy", data, size, options, &errors, &module);
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
