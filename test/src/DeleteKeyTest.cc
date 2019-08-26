// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <assert.h>

#include "pEpEngine.h"
#include "test_util.h"



const string DeleteKeyTests::alice_user_id = PEP_OWN_USERID;
const string DeleteKeyTests::bob_user_id = "BobId";
const string DeleteKeyTests::carol_user_id = "carolId";
const string DeleteKeyTests::dave_user_id = "DaveId";
const string DeleteKeyTests::erin_user_id = "ErinErinErin";
const string DeleteKeyTests::fenris_user_id = "BadWolf";


#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for DeleteKeyTest
    class DeleteKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            DeleteKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~DeleteKeyTest() override {
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

            void import_test_keys() {
                PEP_STATUS status = read_file_and_import_key(session,
                            "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
                assert(status == PEP_KEY_IMPORTED);
                status = set_up_ident_from_scratch(session,
                            "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                            "pep.test.alice@pep-project.org", alice_fpr,
                            alice_user_id.c_str(), "Alice in Wonderland", NULL, true
                        );
                assert(status == PEP_STATUS_OK);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                            "pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), "Bob's Burgers",
                            NULL, false
                        );
                assert(status == PEP_STATUS_OK);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc",
                            "pep-test-carol@pep-project.org", NULL, carol_user_id.c_str(), "Carol Burnett",
                            NULL, false
                        );
                assert(status == PEP_STATUS_OK);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc",
                            "pep-test-dave@pep-project.org", NULL, dave_user_id.c_str(),
                            "David Hasselhoff (Germans Love Me)", NULL, false
                        );
                assert(status == PEP_STATUS_OK);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc",
                            "pep-test-erin@pep-project.org", NULL, erin_user_id.c_str(),
                            "Éirinn go Brách", NULL, false
                        );
                assert(status == PEP_STATUS_OK);

                status = set_up_ident_from_scratch(session,
                            "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                            "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(),
                            "Fenris Leto Hawke", NULL, false
                        );
                assert(status == PEP_STATUS_OK);
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the DeleteKeyTest suite.

    };

}  // namespace


TEST_F(DeleteKeyTest, check_delete_single_pubkey) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, fenris_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, fenris_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    // Great, now delete it.
    status = delete_keypair(session, fenris_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Is it gone?
    status = find_keys(session, fenris_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);

    // Yay.
}

TEST_F(DeleteKeyTest, check_delete_pub_priv_keypair) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, alice_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    // Great, now delete it.
    status = delete_keypair(session, alice_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Is it gone?
    status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);

    // Yay.
}

TEST_F(DeleteKeyTest, check_delete_multiple_keys) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Are they there?
    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, alice_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, dave_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, dave_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, fenris_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, fenris_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    // Great, now delete it.
    status = delete_keypair(session, alice_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, dave_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, fenris_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Is it gone?
    status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);

    status = find_keys(session, dave_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);

    status = find_keys(session, fenris_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);

    // Yay. Make sure everyone else is still there.
    status = find_keys(session, bob_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, bob_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, carol_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, carol_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, erin_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, erin_fpr);
    free_stringlist(keylist);
    keylist = NULL;
}

TEST_F(DeleteKeyTest, check_delete_all_keys) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Are they there?
    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, alice_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, bob_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, bob_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, carol_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, carol_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, dave_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, dave_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, erin_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, erin_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, fenris_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_TRUE(keylist && keylist->value);
    ASSERT_STREQ(keylist->value, fenris_fpr);
    free_stringlist(keylist);
    keylist = NULL;

    // Great, now delete it.
    status = delete_keypair(session, alice_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, bob_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, carol_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, dave_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, erin_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = delete_keypair(session, fenris_fpr);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // Is it gone?
    status = find_keys(session, alice_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, bob_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, carol_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, dave_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, erin_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, fenris_fpr, &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    // Yay.
}

TEST_F(DeleteKeyTest, check_delete_key_not_found) {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    // Great, now delete it.
    status = delete_keypair(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D");
    ASSERT_EQ(status, PEP_KEY_NOT_FOUND);

    // Is it still gone?
    status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    // Yay.
}

TEST_F(DeleteKeyTest, check_delete_empty_keyring) {
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    // Great, now delete it.
    status = delete_keypair(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D");
    ASSERT_EQ(status, PEP_KEY_NOT_FOUND);

    // Is it still gone?
    status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    free_stringlist(keylist);
    keylist = NULL;

    // Yay.
}
