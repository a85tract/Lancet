/*
 * Standalone harness for hb-subset-fuzzer (OSV-2018-161)
 *
 * Bug: heap-buffer-overflow WRITE 1 in BEInt<unsigned short, 2>::set
 *      triggered via OT::Script::subset
 * Root cause: DEFINE_SIZE_ARRAY_SIZED macro used array[0].min_size
 *             instead of array.min_size, causing incorrect size
 *             calculation in get_size() leading to OOB write during
 *             font subsetting.
 *
 * OSS-Fuzz ID: 11081
 * Fix commit: aa5af8d041521507f8bc8ded8a365ee56098388c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <hb.h>
#include <hb-subset.h>

static void
trySubset (hb_face_t *face,
           const hb_codepoint_t text[],
           int text_length,
           bool drop_hints,
           bool drop_layout)
{
  hb_subset_input_t *input = hb_subset_input_create_or_fail ();
  if (!input) return;
  hb_subset_input_set_drop_hints (input, drop_hints);
  hb_subset_input_set_drop_layout (input, drop_layout);
  hb_set_t *codepoints = hb_subset_input_unicode_set (input);

  for (int i = 0; i < text_length; i++)
  {
    hb_set_add (codepoints, text[i]);
  }

  hb_face_t *result = hb_subset (face, input);
  hb_face_destroy (result);

  hb_subset_input_destroy (input);
}

static void
trySubset (hb_face_t *face,
           const hb_codepoint_t text[],
           int text_length)
{
  for (unsigned int drop_hints = 0; drop_hints < 2; drop_hints++)
  {
    for (unsigned int drop_layout = 0; drop_layout < 2; drop_layout++)
    {
      trySubset (face, text, text_length,
                 (bool) drop_hints, (bool) drop_layout);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  hb_blob_t *blob = hb_blob_create ((const char *)data, size,
                                    HB_MEMORY_MODE_READONLY, NULL, NULL);
  hb_face_t *face = hb_face_create (blob, 0);

  hb_set_t *output = hb_set_create();
  hb_face_collect_unicodes (face, output);
  hb_set_destroy (output);

  const hb_codepoint_t text[] =
      {
        'A', 'B', 'C', 'D', 'E', 'X', 'Y', 'Z', '1', '2',
        '3', '@', '_', '%', '&', ')', '*', '$', '!'
      };

  trySubset (face, text, sizeof (text) / sizeof (hb_codepoint_t));

  hb_codepoint_t text_from_data[16];
  if (size > sizeof(text_from_data)) {
    memcpy (text_from_data,
            data + size - sizeof(text_from_data),
            sizeof(text_from_data));
    unsigned int text_size = sizeof (text_from_data) / sizeof (hb_codepoint_t);
    trySubset (face, text_from_data, text_size);
  }

  hb_face_destroy (face);
  hb_blob_destroy (blob);

  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <font-file>\n", argv[0]);
    return 1;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  uint8_t *data = (uint8_t *)malloc(fsize);
  if (!data) {
    fclose(f);
    return 1;
  }

  fread(data, 1, fsize, f);
  fclose(f);

  int ret = LLVMFuzzerTestOneInput(data, fsize);

  free(data);
  return ret;
}
