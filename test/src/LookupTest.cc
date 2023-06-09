// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()
#include "TestConstants.h"

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "keymanagement.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for LookupTest
    class LookupTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            LookupTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~LookupTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NOTNULL(engine);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NOTNULL(engine->session);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the LookupTest suite.

    };

}  // namespace



TEST_F(LookupTest, check_lookup) {
    // 1. create original identity
    const char* expected_address = "hans@xn--bcher-kva.tld";
    const char* fpr = "00B5BB6769B1F451705445E208AD6E9400D38894";
    const char* userid = "Hans";
    const char* username = "SuperDuperHans";
    const string pub_key = slurp("test_keys/pub/hans@xn--bcher-kva.tld_-0x08AD6E9400D38894_pub.asc");

    PEP_STATUS statuspub = import_key(session, pub_key.c_str(), pub_key.length(), NULL);
    ASSERT_EQ(statuspub , PEP_TEST_KEY_IMPORT_SUCCESS);

    pEp_identity* hans = new_identity(expected_address, fpr, userid, username);

    PEP_STATUS status = set_identity(session, hans);
    ASSERT_OK;
    free_identity(hans);

    // Lookup using different spellings of the email address.
    const char *addresses[] = {
        // Check case folding.
        "hans@xn--bcher-kva.tld",
        "Hans@xn--bcher-kva.tld",
        "Hans@xn--Bcher-kva.tld",

        // Check puny code normalization.  Note: only Sequoia does
        // puny code normalization.
#ifdef USE_SEQUOIA
        "hans@bücher.tld",
        "Hans@bücher.tld",
        "HANS@BÜCHER.TLD",
#endif
    };

    for (int i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i ++) {
        const char *address = addresses[i];

        // Actually, all this was ever really doing was testing sequoia's version of find_keys lookup to find the key
        // and return it to update_identity in key election given various variations of the address. pgp_sequoia.c does puny code
        // normalization, but the engine doesn't.

        // So now we test find_keys directly.
        stringlist_t* keylist = NULL;
        PEP_STATUS status = find_keys(session, address, &keylist);
        ASSERT_OK;
        ASSERT_NOTNULL(keylist);
        // We should always get the same fingerprint.
        ASSERT_NOTNULL(keylist->value);
        // Doublecheck FIXME (autogen)
        ASSERT_STREQ(keylist->value, fpr);
        ASSERT_NULL(keylist->next);

        free_stringlist(keylist);

    }
}
