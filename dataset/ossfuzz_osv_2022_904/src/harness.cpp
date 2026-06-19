#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <geos_c.h>

static int initialized = 0;
static FILE *flogOut;

void notice(const char *fmt, ...) {
    va_list ap;
    fprintf(flogOut, "NOTICE: ");
    va_start(ap, fmt);
    vfprintf(flogOut, fmt, ap);
    va_end(ap);
    fprintf(flogOut, "\n");
}

void log_and_exit(const char *fmt, ...) {
    va_list ap;
    fprintf(flogOut, "ERROR: ");
    va_start(ap, fmt);
    vfprintf(flogOut, fmt, ap);
    va_end(ap);
    fprintf(flogOut, "\n");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!initialized) {
        flogOut = fopen("/dev/null", "wb");
        initGEOS(notice, log_and_exit);
        initialized = 1;
    }

    char *wkt = (char *)malloc(size + 1);
    if (!wkt) return 0;
    memcpy(wkt, data, size);
    wkt[size] = '\0';

    GEOSGeometry *geom = GEOSGeomFromWKT(wkt);
    if (geom != NULL) {
        GEOSGeometry *g2 = GEOSBuffer(geom, 1.0, 8);
        if (g2) {
            GEOSGeometry *g3 = GEOSIntersection(geom, g2);
            GEOSGeom_destroy(g3);
            GEOSGeom_destroy(g2);
        }
        char *r = GEOSGeomToWKT(geom);
        free(r);
        GEOSGeom_destroy(geom);
    }
    free(wkt);
    return 0;
}
