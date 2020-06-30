/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include "timestamp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

DYNAMIC_API timestamp * new_timestamp(time_t clock)
{
    timestamp *ts = calloc(1, sizeof(timestamp));
    assert(ts);
    if (ts == NULL)
        return NULL;

    if (clock)
        gmtime_r(&clock, (struct tm *) ts);

    return ts;
}


DYNAMIC_API void free_timestamp(timestamp *ts)
{
    free(ts);
}

DYNAMIC_API timestamp * timestamp_dup(const timestamp *src)
{
    if (!src)
        return NULL;

    timestamp *dst = calloc(1, sizeof(timestamp));
    assert(dst);
    if (!dst)
        return NULL;

    memcpy(dst, src, sizeof(timestamp));
    return dst;
}
