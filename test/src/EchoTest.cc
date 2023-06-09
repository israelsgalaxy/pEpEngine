// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "echo_api.h"
#include "TestConstants.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for EchoTest
    class EchoTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EchoTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EchoTest() override {
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
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
                
                string keystr = slurp("test_keys/priv/bcc_test_dude_0-0x1CCCFC41_priv.asc");
                PEP_STATUS status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);    
                pEp_identity * me = new_identity("bcc_test_dude_0@pep.foundation", "0AE9AA3E320595CF93296BDFA155AC491CCCFC41", PEP_OWN_USERID, "BCC Test Sender");
                status = set_own_key(session, me, "0AE9AA3E320595CF93296BDFA155AC491CCCFC41");
                keystr = slurp("test_keys/pub/bcc_test_dude_0-0x1CCCFC41_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                keystr = slurp("test_keys/pub/bcc_test_dude_1-0xDAC746BE_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                keystr = slurp("test_keys/pub/bcc_test_dude_2-0x53CECCF7_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);    

                free_identity(me);
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
            // Objects declared here can be used by all tests in the EchoTest suite.

    };

}  // namespace

static PEP_STATUS dummyMessageToSend(message* msg) {
    PEP_STATUS status = PEP_STATUS_OK;
    if (msg == nullptr)
        return PEP_UNKNOWN_ERROR;

    std::cerr << "pretending to send the message at " << msg << "\n";
    free_message(msg);
    return PEP_STATUS_OK;
}

TEST_F(EchoTest, check_ping) {
    session->messageToSend = dummyMessageToSend;
    PEP_STATUS status = PEP_UNKNOWN_ERROR;

    // 0AE9AA3E320595CF93296BDFA155AC491CCCFC41
    // D0AF2F9695E186A8DC058B935FE2793DDAC746BE
    pEp_identity* sender = new_identity("bcc_test_dude_0@pep.foundation", NULL, PEP_OWN_USERID, "BCC Test Sender");

    pEp_identity* recip = new_identity("bcc_test_dude_1@pep.foundation", "B36E468E7A381946FCDBDDFA84B1F3E853CECCF7", "TOFU_bcc_test_dude_1@pep.foundation", "BCC Test Recip");

    
    // is this needed?
    status = myself(session, sender);
    ASSERT_OK;
    
    // is this needed?
    status = update_identity(session, recip);
    ASSERT_OK;

    // Do the move.
    status = send_ping(session, sender, recip);
    ASSERT_OK;

    free_identity(sender);
    free_identity(recip);
}
