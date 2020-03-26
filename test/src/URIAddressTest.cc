// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "test_util.h"
#include "TestConstants.h"

#include "pEpEngine.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for URIAddressTest
    class URIAddressTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            URIAddressTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~URIAddressTest() override {
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
            // Objects declared here can be used by all tests in the URIAddressTest suite.

    };

}  // namespace

#if 0
TEST_F(URIAddressTest, check_uri_address_not_a_test) {
    const char* uri_addr = "payto://BIC/SYSTEM";

    pEp_identity* me = new_identity(uri_addr, NULL, "System", NULL);

    PEP_STATUS status = myself(session, me);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr,
                        &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    
    ofstream outfile_pub, outfile_priv;
    outfile_pub.open("test_keys/pub/URI_address_test_key_pub.asc");
    outfile_pub << keydata;    
    outfile_pub.close();
    
    free(keydata);
    keydata = NULL;
    keysize = 0;

    status = export_secret_key(session, me->fpr,
                              &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    
    outfile_priv.open("test_keys/priv/URI_address_test_key_priv.asc");  
    outfile_priv << keydata;
    outfile_priv.close();
}
#endif

// FIXME: URL, URN
TEST_F(URIAddressTest, check_uri_address_genkey) {
    const char* uri_addr = "shark://grrrr/39874293847092837443987492834";
    const char* uname = "GRRRR, the angry shark";

    pEp_identity* me = new_identity(uri_addr, NULL, PEP_OWN_USERID, uname);

    PEP_STATUS status = myself(session, me);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr,
                        &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    // no guarantee of NUL-termination atm.
//    output_stream << keydata << endl;

    free(keydata);
    free_identity(me);
}

TEST_F(URIAddressTest, check_uri_address_genkey_empty_uname) {
    const char* uri_addr = "payto://BIC/SYSTEMB";
    const char* uname = "Jonas's Broken Identity";

    pEp_identity* me = new_identity(uri_addr, NULL, "SystemB", NULL);

    PEP_STATUS status = myself(session, me);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');

    char* keydata = NULL;
    size_t keysize = 0;
    status = export_key(session, me->fpr,
                        &keydata, &keysize);

    ASSERT_GT(keydata && keysize, 0);
    // no guarantee of NUL-termination atm.
//    output_stream << keydata << endl;

    pEp_identity* me_copy = new_identity(uri_addr, NULL, "SystemB", NULL);
    status = myself(session, me_copy);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(me_copy->fpr && me_copy->fpr[0] != '\0');
    ASSERT_TRUE(me_copy->username && me_copy->username[0] != '\0');
        
    free(keydata);
    free_identity(me);
}

TEST_F(URIAddressTest, check_uri_address_encrypt_2_keys_no_uname) {
    const char* uri_addr_a = "payto://BIC/SYSTEMA";    
    const char* uri_addr_b = "payto://BIC/SYSTEMB";
    const char* uid_a = "SystemA";
    const char* uid_b = "SystemB";
    const char* fpr_a = "B425BAC5ED6014AAE8E34381429FA046E70B09F9";
    const char* fpr_b = "80C8BE340FBF59BCB54FAD1B53703426DCC3681E";
    slurp_and_import_key(session, "test_keys/pub/URI_address_test_key0_pub.asc");
    slurp_and_import_key(session, "test_keys/pub/URI_address_test_key1_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/URI_address_test_key0_priv.asc");
    
    pEp_identity* me_setup = new_identity(uri_addr_a, fpr_a, uid_a, uri_addr_a);
    PEP_STATUS status = set_own_key(session, me_setup, fpr_a);    
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* me = new_identity(uri_addr_a, NULL, uid_a, NULL);
    status = myself(session, me);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(me->fpr, nullptr);
    ASSERT_NE(me->username, nullptr);    
    ASSERT_STREQ(me->fpr, fpr_a);
    ASSERT_STREQ(me->username, uri_addr_a);
    
    // Try without a userid
    pEp_identity* you = new_identity(uri_addr_b, NULL, NULL, NULL);
    status = update_identity(session, you);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(you->fpr, nullptr);
    ASSERT_NE(you->username, nullptr);    
    ASSERT_STREQ(you->fpr, fpr_b);
    ASSERT_STREQ(you->username, uri_addr_b);
    ASSERT_NE(you->user_id, nullptr);
    
    // Ok, all good. Let's go with fresh, ugly identities.
    message* msg = new_message(PEP_dir_outgoing);
    pEp_identity* me_from = new_identity(uri_addr_a, NULL, uid_a, NULL);
    // Give this one a UID, we'll check the TOFU while we're at it.
    pEp_identity* you_to = new_identity(uri_addr_b, NULL, uid_b, NULL);        
    msg->from = me_from;
    msg->to = new_identity_list(you_to);
    msg->shortmsg = strdup("Some swift stuff!");            
    msg->longmsg = strdup("Some more swift stuff!");
    
    message* outmsg = NULL;
    status = encrypt_message(session, msg, NULL, &outmsg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(outmsg, nullptr);
    free_message(msg);
    free_message(outmsg);
    free_identity(me_setup);
    free_identity(me);
    free_identity(you);                
}

// FIXME: URL, URN
TEST_F(URIAddressTest, check_uri_address_encrypt) {
    const char* uri_addr = "shark://grrrr/39874293847092837443987492834";
    const char* uname = "GRRRR, the angry shark";

    pEp_identity* me = new_identity(uri_addr, NULL, PEP_OWN_USERID, uname);

    PEP_STATUS status = myself(session, me);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(me->fpr && me->fpr[0] != '\0');


    const char* you_uri_addr = "shark://bait/8uyoi3lu4hl2..dfoif983j4b@%";
    const char* youname = "Nemo, the delicious fish";
    pEp_identity* you = new_identity(you_uri_addr, NULL, "Food for Shark", youname);
    status = generate_keypair(session, you);
    ASSERT_EQ(status , PEP_STATUS_OK);

    stringlist_t* keylist = NULL;
    status = find_keys(session, you_uri_addr, &keylist);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);

    status = update_identity(session, you);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(you->fpr && you->fpr[0] != '\0');

    message* msg = new_message(PEP_dir_outgoing);

    msg->from = me;
    msg->to = new_identity_list(you);
    msg->shortmsg = strdup("Invitation");
    msg->longmsg = strdup("Yo Neems, wanna come over for dinner?");

    message* enc_msg = NULL;
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
    
    // We don't check for anything here??? FIXME! WTF!
}
