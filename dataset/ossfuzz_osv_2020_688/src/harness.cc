#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *ical_string = (char *)malloc(size + 1);
    if (!ical_string) return 0;
    memcpy(ical_string, data, size);
    ical_string[size] = '\0';

    icalcomponent *component = icalparser_parse_string(ical_string);
    if (component) {
        icalcomponent_free(component);
    }

    free(ical_string);
    return 0;
}
