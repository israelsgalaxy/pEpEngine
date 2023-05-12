/**
 * @file    pEp_debug.c
 * @brief   pEp Engine debugging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#define _EXPORT_PEP_ENGINE_DLL
#include "pEp_debug.h"

#include "pEp_internal.h"

#include <stdlib.h>


/* Internal functions.
 * ***************************************************************** */

DYNAMIC_API void pEp_abort_unless_PEP_NOABORT(PEP_SESSION session)
{
    /* No PEP_REQUIRE here, on purpose:
       in this function we do not check that session be non-NULL, in order to be
       more friendly to debugging. */
    PEP_ICS_DUMMY;

    const char *text = ("this was Engine " PEP_ENGINE_VERSION_LONG);

    /* Print some information, useful for people reporting bugs. */
    if (getenv("PEP_NOABORT") == NULL) {
        if (session != NULL)
            LOG_CRITICAL("%s", text);
        else
            fprintf(stderr, "%s\n", text);
        abort();
    }

    /* Otherwise just go on.  This behaviour is useful in the Engine test
       suite. */
    LOG_CRITICAL("at this point we would have aborted, if the environment"
                 " variable PEP_NOABORT were not defined");
}
