/*
 * Standalone harness for hb-subset-fuzzer (OSV-2023-458)
 *
 * Bug: invalid-free in hb_free_impl -> OT::glyf::_free_compiled_subset_glyphs
 *      -> OT::glyf::subset
 * Root cause: In glyf.hh subset(), error handling called
 *             _free_compiled_subset_glyphs on multiple failure paths.
 *             When padded_offsets.alloc() failed after glyphs were
 *             populated, it freed compiled glyphs and returned. But
 *             later code paths could also attempt to free them,
 *             or the ordering of serialize vs _add_loca_and_head
 *             caused double-free/invalid-free on error.
 *
 * OSS-Fuzz ID: 59592
 * Fix commit: af3fdf1f9e09fb7e47d4528d81fd510730b80745
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <hb.h>
#include <hb-subset.h>

/* Link to the alloc_state from failing-alloc.c in libharfbuzz.
 * When HB_IS_IN_FUZZER is defined and fuzzer_ldflags is set,
 * libharfbuzz exports alloc_state and uses it to simulate
 * allocation failures. Setting alloc_state != 0 causes 1/16
 * of allocations to randomly fail, triggering error paths. */
extern "C" int alloc_state;

static inline int
_fuzzing_alloc_state (const uint8_t *data, size_t size)
{
  if (size && data[size - 1] < 0x80)
    return 0;
  return size;
}

static void
trySubset (hb_face_t *face,
           const hb_codepoint_t text[],
           int text_length,
           unsigned flag_bits,
           hb_subset_input_t *input)
{
  if (!input) return;

  hb_subset_input_set_flags (input, (hb_subset_flags_t) flag_bits);

  hb_set_t *codepoints = hb_subset_input_unicode_set (input);

  for (int i = 0; i < text_length; i++)
    hb_set_add (codepoints, text[i]);

  hb_face_t *result = hb_subset_or_fail (face, input);
  if (result)
  {
    hb_blob_t *blob = hb_face_reference_blob (result);
    unsigned int length;
    const char *data = hb_blob_get_data (blob, &length);

    unsigned int bytes_count = 0;
    for (unsigned int i = 0; i < length; ++i)
      if (data[i]) ++bytes_count;
    assert (bytes_count || !length);

    hb_blob_destroy (blob);
  }
  hb_face_destroy (result);

  hb_subset_input_destroy (input);
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  alloc_state = _fuzzing_alloc_state (data, size);

  hb_blob_t *blob = hb_blob_create ((const char *) data, size,
                                    HB_MEMORY_MODE_READONLY, nullptr, nullptr);
  hb_face_t *face = hb_face_create (blob, 0);

  hb_set_t *output = hb_set_create ();
  hb_face_collect_unicodes (face, output);
  hb_set_destroy (output);

  unsigned flags = HB_SUBSET_FLAGS_DEFAULT;
  const hb_codepoint_t text[] =
      {
        'A', 'B', 'C', 'D', 'E', 'X', 'Y', 'Z', '1', '2',
        '3', '@', '_', '%', '&', ')', '*', '$', '!'
      };

  hb_subset_input_t *input = hb_subset_input_create_or_fail ();
  if (!input)
  {
    hb_face_destroy (face);
    hb_blob_destroy (blob);
    return 0;
  }
  trySubset (face, text, sizeof (text) / sizeof (hb_codepoint_t), flags, input);

  unsigned num_axes;
  hb_codepoint_t text_from_data[16];
  if (size > sizeof (text_from_data) + sizeof (flags) + sizeof(num_axes)) {
    hb_subset_input_t *input = hb_subset_input_create_or_fail ();
    if (!input)
    {
      hb_face_destroy (face);
      hb_blob_destroy (blob);
      return 0;
    }
    size -= sizeof (text_from_data);
    memcpy (text_from_data,
            data + size,
            sizeof (text_from_data));

    size -= sizeof (flags);
    memcpy (&flags,
            data + size,
            sizeof (flags));

    size -= sizeof (num_axes);
    memcpy (&num_axes,
            data + size,
            sizeof (num_axes));

    if (num_axes > 0 && num_axes < 8 && size > num_axes * (sizeof(hb_tag_t) + sizeof(int)))
    {
      for (unsigned i = 0; i < num_axes; i++) {
        hb_tag_t tag;
        int value;
        size -= sizeof (tag);
        memcpy (&tag,
                data + size,
                sizeof (tag));
        size -= sizeof (value);
        memcpy (&value,
                data + size,
                sizeof (value));

        hb_subset_input_pin_axis_location(input,
                                          face,
                                          tag,
                                          (float) value);
      }
    }

    unsigned int text_size = sizeof (text_from_data) / sizeof (hb_codepoint_t);
    trySubset (face, text_from_data, text_size, flags, input);
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
