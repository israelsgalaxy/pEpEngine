#include <stdlib.h>
#include <string>
#include <cstring>

#include "internal_format.h"

#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ElevatedAttachmentsTest
    class ElevatedAttachmentsTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ElevatedAttachmentsTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ElevatedAttachmentsTest() override {
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
                engine->prep(NULL, NULL, init_files);

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
            // Objects declared here can be used by all tests in the ElevatedAttachmentsTest suite.

    };

}  // namespace


TEST_F(ElevatedAttachmentsTest, check_internal_format) {
    const char *data = "simulated data";
    size_t data_size = strlen(data) + 1;

    char *code;
    size_t code_size;

    // test PGP keys

    PEP_STATUS status = encode_internal(data, data_size, "application/pgp-keys", &code, &code_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_EQ(code_size, data_size + 4);

    ASSERT_EQ(code[0], 0);
    ASSERT_EQ(code[1], 'K');
    ASSERT_EQ(code[2], 2);

    ASSERT_STREQ(code + 4, data);

    // decode

    char *value;
    size_t size;
    char *mime_type;

    status = decode_internal(code, code_size, &value, &size, &mime_type);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_EQ(size, data_size);
    ASSERT_STREQ(value, data);
    ASSERT_STREQ(mime_type, "application/pgp-keys");

    free(value);
    free(code);

    // test Sync

    status = encode_internal(data, data_size, "application/pEp.sync", &code, &code_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_EQ(code_size, data_size + 4);

    ASSERT_EQ(code[0], 0);
    ASSERT_EQ(code[1], 'S');
    ASSERT_EQ(code[2], 0);

    ASSERT_STREQ(code + 4, data);

    // decode

    status = decode_internal(code, code_size, &value, &size, &mime_type);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_EQ(size, data_size);
    ASSERT_STREQ(value, data);
    ASSERT_STREQ(mime_type, "application/pEp.sync");

    free(value);
    free(code);

    // test Distribution

    status = encode_internal(data, data_size, "application/pEp.distribution", &code, &code_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_EQ(code_size, data_size + 4);

    ASSERT_EQ(code[0], 0);
    ASSERT_EQ(code[1], 'D');
    ASSERT_EQ(code[2], 0);

    ASSERT_STREQ(code + 4, data);

    // decode

    status = decode_internal(code, code_size, &value, &size, &mime_type);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_EQ(size, data_size);
    ASSERT_STREQ(value, data);
    ASSERT_STREQ(mime_type, "application/pEp.distribution");

    free(value);
    free(code);

    // test PGP signature

    status = encode_internal(data, data_size, "application/pgp-signature", &code, &code_size);
    ASSERT_EQ(status, PEP_STATUS_OK);
    
    ASSERT_EQ(code_size, data_size + 4);

    ASSERT_EQ(code[0], 0);
    ASSERT_EQ(code[1], 'A');
    ASSERT_EQ(code[2], 2);

    ASSERT_STREQ(code + 4, data);

    // decode

    status = decode_internal(code, code_size, &value, &size, &mime_type);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASSERT_EQ(size, data_size);
    ASSERT_STREQ(value, data);
    ASSERT_STREQ(mime_type, "application/pgp-signature");

    free(value);
    free(code);
}

TEST_F(ElevatedAttachmentsTest, check_encrypt_decrypt_message) {
    // a message from me, Alice, to Bob

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    ASSERT_EQ(status , PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", alice_fpr,
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"));

    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "Bob", NULL);
    status = myself(session, alice);
    ASSERT_EQ(status , PEP_STATUS_OK);
    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = set_as_pEp_user(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);

    msg->to = new_identity_list(bob);
    msg->from = alice;
    msg->shortmsg = strdup("Yo Bob!");
    msg->longmsg = strdup("Look at my hot new sender fpr field!");

    message* enc_msg = NULL;

    // encrypt this message inline

    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_inline, 0);
    ASSERT_EQ(status , PEP_STATUS_OK);
    
    // .shortmsg will stay unencrypted
    ASSERT_STREQ(msg->shortmsg, enc_msg->shortmsg);

    // .longmsg will go encrypted
    ASSERT_TRUE(is_PGP_message_text(enc_msg->longmsg));

    free_message(msg);
    free_message(enc_msg);
}

