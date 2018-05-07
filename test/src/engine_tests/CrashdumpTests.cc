// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include "EngineTestSessionSuite.h"
#include "CrashdumpTests.h"

using namespace std;

CrashdumpTests::CrashdumpTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    TEST_ADD(CrashdumpTests::check_crashdump);
}

void CrashdumpTests::check_crashdump() {
    // MODULE test code
    char *text;
    PEP_STATUS status2 = get_crashdump_log(session, 0, &text);
    TEST_ASSERT(status2 == PEP_STATUS_OK);
    cout << text;
}
