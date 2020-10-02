#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

/* This is just a quick shell to insert messages and databases into for quick testing during debugging. */

namespace {

	//The fixture for BareEncryptShellTest
    class BareEncryptShellTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            // change these in the constructor to paths you want passed in for the test. They can be empty.
            std::string message_to_encrypt;
            std::string keys_db_to_init;
            std::string mgmt_db_to_init;
        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            BareEncryptShellTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;

                message_to_encrypt = "";
                keys_db_to_init = "";
                mgmt_db_to_init = "";

            }

            ~BareEncryptShellTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();
                if (!keys_db_to_init.empty())
                    init_files.push_back(std::pair<std::string, std::string>(keys_db_to_init, std::string("keys.db")));

                if (!mgmt_db_to_init.empty())
                    init_files.push_back(std::pair<std::string, std::string>(mgmt_db_to_init, std::string("management.db")));

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
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
            // Objects declared here can be used by all tests in the BareEncryptShellTest suite.

    };

}  // namespace


TEST_F(BareEncryptShellTest, check_bare_encrypt_shell) {
    char* outmsg = NULL;
    PEP_STATUS status = MIME_encrypt_message(session, message_to_encrypt.c_str(), message_to_encrypt.size(), NULL, &outmsg, PEP_enc_auto, 0);
    ASSERT_OK;
}
