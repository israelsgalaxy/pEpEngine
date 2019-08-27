// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <cstring>
#include <iostream>
#include <fstream>

#include "pEpEngine.h"
#include "platform.h"
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for ReencryptPlusExtraKeysTest
    class ReencryptPlusExtraKeysTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ReencryptPlusExtraKeysTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ReencryptPlusExtraKeysTest() override {
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
            // Objects declared here can be used by all tests in the ReencryptPlusExtraKeysTest suite.

    };

}  // namespace


TEST_F(ReencryptPlusExtraKeysTest, check_reencrypt_plus_extra_keys) {
    PEP_STATUS status = PEP_STATUS_OK;

    /* import all the keys */
    const char* fpr_own_recip_key = "85D022E0CC9BA9F6B922CA7B638E5211B1A2BE89";
    const char* fpr_own_recip_2_key = "7A2EEB933E6FD99207B83E397B6D3751D6E75FFF";

    const char* fpr_sender_pub_key = "95FE24B262A34FA5C6A8D0AAF90144FC3B508C8E";
    const char* fpr_recip_2_pub_key = "60701073D138EF622C8F9221B6FC86831EDBE691";
    const char* fpr_recip_0_pub_key = "CDF787C7C9664E02825DD416C6FBCF8D1F4A5986";
    // we're leaving recip_1 out for the Hell of it - D3886D0DF75113BE2799C9374D6B99FE0F8273D8
    const char* fpr_pub_extra_key_0 = "33BB6C92EBFB6F29641C75B5B79D916C828AA789";

    const char* fpr_pub_extra_key_1 = "3DB93A746785FDD6110798AB3B193A9E8B026AEC";
    const string own_recip_pub_key = slurp("test_keys/pub/reencrypt_recip_0-0xB1A2BE89_pub.asc");
    const string own_recip_priv_key = slurp("test_keys/priv/reencrypt_recip_0-0xB1A2BE89_priv.asc");
    const string own_recip_2_pub_key = slurp("test_keys/pub/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_pub.asc");
    const string own_recip_2_priv_key = slurp("test_keys/priv/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_priv.asc");

    const string sender_pub_key = slurp("test_keys/pub/reencrypt_sender_0-0x3B508C8E_pub.asc");
    const string recip_2_pub_key = slurp("test_keys/pub/reencrypt_other_recip_2-0x1EDBE691_pub.asc");
    const string recip_0_pub_key = slurp("test_keys/pub/reencrypt_other_recip_0-0x1F4A5986_pub.asc");
    // we're leaving recip_1 out for the Hell of it
    const string pub_extra_key_0 = slurp("test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc");
    const string pub_extra_key_1 = slurp("test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc");

    status = import_key(session, own_recip_pub_key.c_str(), own_recip_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, own_recip_priv_key.c_str(), own_recip_priv_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, own_recip_2_pub_key.c_str(), own_recip_2_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, own_recip_2_priv_key.c_str(), own_recip_2_priv_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    status = import_key(session, sender_pub_key.c_str(), sender_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, recip_2_pub_key.c_str(), recip_2_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, recip_0_pub_key.c_str(), recip_0_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, pub_extra_key_0.c_str(), pub_extra_key_0.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, pub_extra_key_1.c_str(), pub_extra_key_1.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    output_stream << "Keys imported." << endl;

    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");

    output_stream << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    ASSERT_EQ(status , PEP_STATUS_OK);
    output_stream << "Done: inserting own identities and keys into database." << endl;

    const string to_reencrypt_from_enigmail = slurp("test_mails/reencrypt_sent_by_enigmail.eml");
    const string to_reencrypt_from_enigmail_BCC = slurp("test_mails/reencrypt_BCC_sent_by_enigmail.eml");
    const string to_reencrypt_from_pEp = slurp("test_mails/reencrypt_encrypted_through_pEp.eml");

    output_stream << endl << "Case 1a: Calling MIME_decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 with no extra keys." << endl;

    char* decrypted_text = nullptr;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;

    flags = PEP_decrypt_flag_untrusted_server;
    char* modified_src = NULL;

    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &modified_src);

    output_stream << decrypted_text << endl;

    output_stream << "Status is " << tl_status_string(status) << endl;
    ASSERT_NE(decrypted_text , nullptr);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);

    ASSERT_EQ(modified_src , nullptr);
    //output_stream << modified_src << endl;

    free(decrypted_text);
    decrypted_text = nullptr;

    output_stream << "Case 1a: PASS" << endl << endl;

    output_stream << "Case 1b: Calling MIME_decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 extra keys." << endl;

    // In: extra keys; Out: keys that were used to encrypt this.
    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail.c_str(),
                                  to_reencrypt_from_enigmail.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &modified_src);

    output_stream << decrypted_text << endl;
    output_stream << "Status is " << tl_status_string(status) << endl;


    ASSERT_NE(decrypted_text , nullptr);
    ASSERT_NE(modified_src , nullptr);

    free(decrypted_text);
    decrypted_text = nullptr;

    output_stream << "CHECK: Decrypting to see what keys it was encrypted for." << endl;

    free(decrypted_text);
    decrypted_text = nullptr;
    flags = 0;
    char* throwaway = NULL;

    status = MIME_decrypt_message(session,
                                  modified_src,
                                  strlen(modified_src),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &throwaway);

    output_stream << "keys used:\n";

    bool own_key_found = false;
    bool extra_key_0_found = false;
    bool extra_key_1_found = false;

    int i = 0;

    if (keys && keys->next)
        dedup_stringlist(keys->next);

    for (stringlist_t* kl = keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
              ASSERT_EQ(strcasecmp(fpr_own_recip_2_key,kl->value) , 0);
        }
        else {
            if (strcasecmp(fpr_own_recip_2_key, kl->value) == 0) {
                output_stream << "Encrypted for us." << endl;
                own_key_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0) {
                output_stream << "Encrypted for extra key 0." << endl;
                extra_key_0_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0) {
                output_stream << "Encrypted for extra key 1." << endl;
                extra_key_1_found = true;
            }
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
                ASSERT_TRUE(false);
            }
            output_stream << "\t " << kl->value << endl;
        }
        ASSERT_LT(i , 4);
    }
    ASSERT_TRUE(own_key_found && extra_key_0_found && extra_key_1_found);
    output_stream << "Message was encrypted for all the keys it should be, and none it should not!" << endl;

    output_stream << "Case 1b: PASS" << endl << endl;

    output_stream << "Case 2a: Calling MIME_decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with no extra keys." << endl;

    free(modified_src);
    modified_src = NULL;

    free_stringlist(keys);
    keys = NULL;

    flags = PEP_decrypt_flag_untrusted_server;

    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail_BCC.c_str(),
                                  to_reencrypt_from_enigmail_BCC.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &modified_src);

    output_stream << (decrypted_text ? decrypted_text : "No decrypted text") << endl;
    output_stream << "Status is " << tl_status_string(status) << endl;

    ASSERT_NE(decrypted_text , nullptr);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_EQ(modified_src , nullptr);

    free(decrypted_text);
    decrypted_text = nullptr;


    output_stream << "Case 2a: PASS" << endl << endl;

    output_stream << "Case 2b: Calling MIME_decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with extra keys." << endl;

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_enigmail_BCC.c_str(),
                                  to_reencrypt_from_enigmail_BCC.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &modified_src);

    output_stream << decrypted_text << endl;
    output_stream << "Status is " << tl_status_string(status) << endl;

    ASSERT_NE(decrypted_text , nullptr);
    ASSERT_NE(modified_src , nullptr);

    free(decrypted_text);
    decrypted_text = nullptr;

    output_stream << "CHECK: Decrypting to see what keys it was encrypted for." << endl;

    free(decrypted_text);
    decrypted_text = nullptr;
    flags = 0;
    throwaway = NULL;

    status = MIME_decrypt_message(session,
                                  modified_src,
                                  strlen(modified_src),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &throwaway);

    output_stream << "keys used:\n";

    own_key_found = false;
    extra_key_0_found = false;
    extra_key_1_found = false;

    i = 0;

    if (keys->next)
        dedup_stringlist(keys->next);

    for (stringlist_t* kl = keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
              // ASSERT_EQ(strcasecmp(fpr_own_recip_2_key,kl->value) , 0);
        }
        else {
            if (strcasecmp(fpr_own_recip_2_key, kl->value) == 0) {
                output_stream << "Encrypted for us." << endl;
                own_key_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0) {
                output_stream << "Encrypted for extra key 0." << endl;
                extra_key_0_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0) {
                output_stream << "Encrypted for extra key 1." << endl;
                extra_key_1_found = true;
            }
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
                // TEST_ASSERT_MSG(false, "Encrypted for someone it shouldn't have been.");
            }
            output_stream << "\t " << kl->value << endl;
        }
        ASSERT_LT(i , 4);
    }
//        TEST_ASSERT_MSG(own_key_found && extra_key_0_found && extra_key_1_found, "Not encrypted for all desired keys.");

    output_stream << "Message was encrypted for all the keys it should be, and none it should not!" << endl;

    output_stream << "Case 2b: PASS" << endl << endl;

    output_stream << "Case 3a: Calling MIME_decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with no extra keys." << endl;
    free(modified_src);
    modified_src = NULL;

    free_stringlist(keys);
    keys = NULL;

    status = set_own_key(session, me_recip_1, fpr_own_recip_key);
    ASSERT_EQ(status , PEP_STATUS_OK);

    flags = PEP_decrypt_flag_untrusted_server;

    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_pEp.c_str(),
                                  to_reencrypt_from_pEp.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &modified_src);

    output_stream << decrypted_text << endl;
    output_stream << "Status is " << tl_status_string(status) << endl;

    ASSERT_NE(decrypted_text , nullptr);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_EQ(modified_src , nullptr);

    free(decrypted_text);
    decrypted_text = nullptr;

    output_stream << "Case 3a: PASS" << endl << endl;


    output_stream << "Case 3b: Calling MIME_decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with extra keys." << endl;

    free_stringlist(keys);
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    status = MIME_decrypt_message(session,
                                  to_reencrypt_from_pEp.c_str(),
                                  to_reencrypt_from_pEp.size(),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &modified_src);

    output_stream << decrypted_text << endl;
    output_stream << "Status is " << tl_status_string(status) << endl;

    ASSERT_NE(decrypted_text , nullptr);

    free(decrypted_text);
    decrypted_text = nullptr;

    output_stream << "CHECK: Decrypting to see what keys it was encrypted for." << endl;

    free(decrypted_text);
    decrypted_text = nullptr;
    flags = 0;
    throwaway = NULL;

    status = MIME_decrypt_message(session,
                                  modified_src,
                                  strlen(modified_src),
                                  &decrypted_text,
                                  &keys,
                                  &rating,
                                  &flags,
                                  &throwaway);

    output_stream << "keys used:\n";

    own_key_found = false;
    extra_key_0_found = false;
    extra_key_1_found = false;

    i = 0;

    if (keys->next)
    dedup_stringlist(keys->next);
;

    for (stringlist_t* kl = keys; kl && kl->value; kl = kl->next, i++)
    {
        if (i == 0) {
              output_stream << "Signed by " << (strcasecmp("", kl->value) == 0 ? "NOBODY" : kl->value) << endl;
//              TEST_ASSERT_MSG(strcasecmp(fpr_own_recip_key,kl->value) == 0);
        }
        else {
            if (strcasecmp(fpr_own_recip_key, kl->value) == 0) {
                output_stream << "Encrypted for us." << endl;
                own_key_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_0, kl->value) == 0) {
                output_stream << "Encrypted for extra key 0." << endl;
                extra_key_0_found = true;
            }
            else if (strcasecmp(fpr_pub_extra_key_1, kl->value) == 0) {
                output_stream << "Encrypted for extra key 1." << endl;
                extra_key_1_found = true;
            }
            else {
                output_stream << "FAIL: Encrypted for " << kl->value << ", which it should not be." << endl;
//                TEST_ASSERT_MSG(false);
            }
            output_stream << "\t " << kl->value << endl;
        }
        ASSERT_LT(i , 4);
    }
//    TEST_ASSERT_MSG(own_key_found && extra_key_0_found && extra_key_1_found);
    output_stream << "Message was encrypted for all the keys it should be, and none it should not!" << endl;

    output_stream << "Case 3b: PASS" << endl << endl;

}

TEST_F(ReencryptPlusExtraKeysTest, check_efficient_reencrypt) {
    PEP_STATUS status = PEP_STATUS_OK;

    /* import all the keys */
    const char* fpr_own_recip_key = "85D022E0CC9BA9F6B922CA7B638E5211B1A2BE89";
    const char* fpr_own_recip_2_key = "7A2EEB933E6FD99207B83E397B6D3751D6E75FFF";

    const char* fpr_sender_pub_key = "95FE24B262A34FA5C6A8D0AAF90144FC3B508C8E";
    const char* fpr_recip_2_pub_key = "60701073D138EF622C8F9221B6FC86831EDBE691";
    const char* fpr_recip_0_pub_key = "CDF787C7C9664E02825DD416C6FBCF8D1F4A5986";
    // we're leaving recip_1 out for the Hell of it - D3886D0DF75113BE2799C9374D6B99FE0F8273D8
    const char* fpr_pub_extra_key_0 = "33BB6C92EBFB6F29641C75B5B79D916C828AA789";

    const char* fpr_pub_extra_key_1 = "3DB93A746785FDD6110798AB3B193A9E8B026AEC";
    const string own_recip_pub_key = slurp("test_keys/pub/reencrypt_recip_0-0xB1A2BE89_pub.asc");
    const string own_recip_priv_key = slurp("test_keys/priv/reencrypt_recip_0-0xB1A2BE89_priv.asc");
    const string own_recip_2_pub_key = slurp("test_keys/pub/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_pub.asc");
    const string own_recip_2_priv_key = slurp("test_keys/priv/reencrypt_recip_numero_deux_test_0-0xD6E75FFF_priv.asc");

    const string sender_pub_key = slurp("test_keys/pub/reencrypt_sender_0-0x3B508C8E_pub.asc");
    const string recip_2_pub_key = slurp("test_keys/pub/reencrypt_other_recip_2-0x1EDBE691_pub.asc");
    const string recip_0_pub_key = slurp("test_keys/pub/reencrypt_other_recip_0-0x1F4A5986_pub.asc");
    // we're leaving recip_1 out for the Hell of it
    const string pub_extra_key_0 = slurp("test_keys/pub/reencrypt_extra_keys_0-0x828AA789_pub.asc");
    const string pub_extra_key_1 = slurp("test_keys/pub/reencrypt_extra_keys_1-0x8B026AEC_pub.asc");

    status = import_key(session, own_recip_pub_key.c_str(), own_recip_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, own_recip_priv_key.c_str(), own_recip_priv_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, own_recip_2_pub_key.c_str(), own_recip_2_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, own_recip_2_priv_key.c_str(), own_recip_2_priv_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    status = import_key(session, sender_pub_key.c_str(), sender_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, recip_2_pub_key.c_str(), recip_2_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, recip_0_pub_key.c_str(), recip_0_pub_key.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, pub_extra_key_0.c_str(), pub_extra_key_0.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);
    status = import_key(session, pub_extra_key_1.c_str(), pub_extra_key_1.length(), NULL);
    ASSERT_EQ(status , PEP_TEST_KEY_IMPORT_SUCCESS);

    output_stream << "Keys imported." << endl;

    pEp_identity* me_recip_1 = new_identity("reencrypt_recip@darthmama.cool", fpr_own_recip_key, PEP_OWN_USERID, "Me Recipient");
    pEp_identity* me_recip_2 = new_identity("reencrypt_recip_numero_deux_test@darthmama.org", fpr_own_recip_2_key, PEP_OWN_USERID, "Me Recipient");

    output_stream << "Inserting own identities and keys into database." << endl;
    status = set_own_key(session, me_recip_2, fpr_own_recip_2_key);
    ASSERT_EQ(status , PEP_STATUS_OK);
    output_stream << "Done: inserting own identities and keys into database." << endl;

    const string to_reencrypt_from_enigmail = slurp("test_mails/reencrypt_sent_by_enigmail.eml");
    const string to_reencrypt_from_enigmail_BCC = slurp("test_mails/reencrypt_BCC_sent_by_enigmail.eml");
    const string to_reencrypt_from_pEp = slurp("test_mails/reencrypt_encrypted_through_pEp.eml");

    output_stream << endl << "Case 1a: Calling MIME_decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 with no extra keys." << endl;

    message* dec_msg = NULL;
    message* enc_msg = NULL;

    // In: extra keys; Out: keys that were used to encrypt this.
    stringlist_t* keys = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;

    flags = PEP_decrypt_flag_untrusted_server;

    output_stream << "Case 1: Calling MIME_decrypt_message with reencrypt flag set on message sent from enigmail for recip 2 extra keys." << endl;

    // In: extra keys; Out: keys that were used to encrypt this.
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    status = mime_decode_message(to_reencrypt_from_enigmail.c_str(), to_reencrypt_from_enigmail.size(), &enc_msg);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg , nullptr);

    status = decrypt_message(session, enc_msg, &dec_msg, &keys, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_NE(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NE(enc_msg , nullptr);

    output_stream << "CHECK: Do it again, and make sure there's no modified source!" << endl;

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;

    status = decrypt_message(session, enc_msg, &dec_msg, &keys, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified , 0);
    ASSERT_NE(enc_msg , nullptr);
    ASSERT_NE(dec_msg->_sender_fpr, nullptr);
    ASSERT_NE(keys, nullptr);
    ASSERT_STRNE(dec_msg->_sender_fpr, keys->value);

    output_stream << "PASS: Test 1" << endl << endl;

    output_stream << "Case 2: Calling MIME_decrypt_message with reencrypt flag set on message sent with recip 2 in BCC from enigmail with extra keys." << endl;
    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    status = mime_decode_message(to_reencrypt_from_enigmail_BCC.c_str(), to_reencrypt_from_enigmail_BCC.size(), &enc_msg);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg , nullptr);

    status = decrypt_message(session, enc_msg, &dec_msg, &keys, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_NE(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NE(enc_msg , nullptr);

    output_stream << "CHECK: Do it again, and make sure there's no modified source!" << endl;

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;

    status = decrypt_message(session, enc_msg, &dec_msg, &keys, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NE(enc_msg , nullptr);
    ASSERT_NE(dec_msg->_sender_fpr, nullptr);
    ASSERT_NE(keys, nullptr);
    ASSERT_STRNE(dec_msg->_sender_fpr, keys->value);


    output_stream << "PASS: Test 2" << endl << endl;

    output_stream << "Case 3: Calling MIME_decrypt_message with reencrypt flag set on message generated by pEp (message 2.0) with extra keys." << endl;

    keys = new_stringlist(fpr_pub_extra_key_0);
    stringlist_add(keys, fpr_pub_extra_key_1);

    flags = PEP_decrypt_flag_untrusted_server;

    status = mime_decode_message(to_reencrypt_from_pEp.c_str(), to_reencrypt_from_pEp.size(), &enc_msg);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_msg , nullptr);

    status = decrypt_message(session, enc_msg, &dec_msg, &keys, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_NE(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NE(enc_msg , nullptr);

    output_stream << "CHECK: Do it again, and make sure there's no modified source!" << endl;

    free_message(dec_msg);
    dec_msg = NULL;
    flags = PEP_decrypt_flag_untrusted_server;

    status = decrypt_message(session, enc_msg, &dec_msg, &keys, &rating, &flags);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(dec_msg , nullptr);
    ASSERT_EQ(flags & PEP_decrypt_flag_src_modified, 0);
    ASSERT_NE(enc_msg , nullptr);
    ASSERT_NE(dec_msg->_sender_fpr, nullptr);
    ASSERT_NE(keys, nullptr);
    ASSERT_STRNE(dec_msg->_sender_fpr, keys->value);

    output_stream << "PASS: Test 3" << endl << endl;

}