// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()
#include "TestConstants.h"

#include "pEpEngine.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "KeyringImportTests.h"

using namespace std;

void KeyringImportTests::setup() {
    EngineTestSessionSuite::setup();
}

void KeyringImportTests::tear_down() {
    EngineTestSessionSuite::tear_down();
}

KeyringImportTests::KeyringImportTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    // I have no idea how this should behave outside of Sequoia. Neal, please fix.
#ifdef USE_SEQUOIA                        
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyringImportTests::import1"),
                                                                      static_cast<Func>(&KeyringImportTests::import1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("KeyringImportTests::import2"),
                                                                      static_cast<Func>(&KeyringImportTests::import2)));
}


void KeyringImportTests::import1() {
    const string pub_key = slurp("test_keys/pub/pep-test-keyring.asc");

    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    struct entry {
        const char *fingerprint;
        const char *address;
    };

    struct entry entries[] = {
      { "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
        "pep.test.alice@pep-project.org" },
      { "3D8D9423D03DDF61B60161150313D94A1CCBC7D7",
        "pep.test.apple@pep-project.org" },
      { "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39",
        "pep.test.bob@pep-project.org" },
      { "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42",
        "pep-test-carol@pep-project.org" },
      { "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6",
        "pep-test-dave@pep-project.org" },
      { "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA",
        "pep-test-erin@pep-project.org" },
      { "B022B74476D8A8E1F01E55FBAB6972569A7FC670",
        "pep-test-frank@pep-project.org" },
      { "906C9B8349954E82C5623C3C8C541BD4E203586C",
        "pep-test-gabrielle@pep-project.org" },
      { "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575",
        "pep.test.john@pep-project.org" },
    };

    for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i ++) {
        const char *address = entries[i].address;
        const char *fpr = entries[i].fingerprint;

        cout << "Looking up: " << address << ", should have fingerprint: " << fpr << endl;
        pEp_identity *id = new_identity(address, NULL, NULL, NULL);
        PEP_STATUS status = update_identity(session, id);
        TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
        cout << "Got: " << (id->fpr ?: "NULL") << " -> " << (id->address ?: "NULL") << endl;

        // We should always get the same fingerprint.
        TEST_ASSERT_MSG((id->fpr), "id->fpr");
        TEST_ASSERT_MSG((strcmp(id->fpr, fpr) == 0), "strcmp(id->fpr, fpr) == 0");

        free_identity(id);
    }
}

void KeyringImportTests::import2() {
    const string pub_key = slurp("test_keys/pub/pep-test-android-keyring.pgp");

    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    struct entry {
        const char *fingerprint;
        const char *address;
    };

    // Several addresses appear multiple times in the keyring.  To
    // avoid teaching this function how key election works, we just
    // don't test those.
    struct entry entries[] = {
      // { "1D600EA0BD575C846E0A8C1008BE097B1F15FB26",
      //   "android01@peptest.ch" },
      // { "51FBBE53E9643A69D6D1F60E74E8073E2DD1F4AC",
      //   "test010@peptest.ch" },
      { "DB92DA58C7F6D6A48F7EF9DC4EBB4CED0E93C7B3",
        "thomas@o365.peptest.ch" },
      { "667A749BEC0C6F844D499D57851E58B37BD4B02E",
        "iostest009@peptest.ch" },
      { "7FCCC380455A9C2F1B080E18CEFBF78746423688",
        "iostest006@peptest.ch" },
      // { "447C595819EDB241",
      //   "android02@peptest.ch" },
      // { "474D7DE519248C2A2EFD45A2148BBDB8A9C68A1C",
      //   "test010@peptest.ch" },
      { "DBA0A1A1001396838E3A3269DF2ED8AA4A3144AA",
        "sva@pep-security.net" },
      { "DBA0A1A1001396838E3A3269DF2ED8AA4A3144AA",
        "bernadette@pep-security.net" },
      { "DBA0A1A1001396838E3A3269DF2ED8AA4A3144AA",
        "bernadette.laengle@pep.foundation" },
      { "DBA0A1A1001396838E3A3269DF2ED8AA4A3144AA",
        "sva@pep.foundation" },
      { "1E02952E9E2048ABD510261AF43CDF9D0F14C2DB",
        "pepegrillodev@gmail.com" },
      // { "E3549B2DCD26832F4F30D8D051716A5DF1F4C2BF",
      //   "android01@peptest.ch" },
      { "5CC67646D67A33D8A2E4FF849E61B9BC790E6B02",
        "huss@pep-project.org" },
      // { "911BD458F82249F0",
      //   "android02@peptest.ch" },
    };

    for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i ++) {
        const char *address = entries[i].address;
        const char *fpr = entries[i].fingerprint;

        cout << "Looking up: " << address << ", should have fingerprint: " << fpr << endl;
        pEp_identity *id = new_identity(address, NULL, NULL, NULL);
        PEP_STATUS status = update_identity(session, id);
        TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
        cout << "Got: " << (id->fpr ?: "NULL") << " (expected: " << fpr << ") -> " << (id->address ?: "NULL") << endl;

        // We should always get the same fingerprint.
        TEST_ASSERT_MSG((id->fpr), "id->fpr");
        TEST_ASSERT_MSG((strcmp(id->fpr, fpr) == 0), "strcmp(id->fpr, fpr) == 0");

        free_identity(id);
    }
#endif    
}
