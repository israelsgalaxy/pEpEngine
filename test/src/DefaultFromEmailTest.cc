#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>

#define DEFAULT_FROM_TEST_GEN 1

namespace {

	//The fixture for DefaultFromEmailTest
    class DefaultFromEmailTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            DefaultFromEmailTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~DefaultFromEmailTest() override {
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

            const char* john_fpr = "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575";
            const char* inq_fpr = "8E8D2381AE066ABE1FEE509821BA977CA4728718";
            string mail_prefix = "test_mails/default_keys_test_ver_";
            string mail_suffix = string(".eml");
            string OpenPGP_file = mail_prefix + "OpenPGP" + mail_suffix;
            string v1_0_file = mail_prefix + "1.0" + mail_suffix;
            string v2_0_file = mail_prefix + "2.0" + mail_suffix;
            string v2_1_file = mail_prefix + "2.1" + mail_suffix;
            string v2_2_file = mail_prefix + "2.2" + mail_suffix;
            string v10_111_file = mail_prefix + "10.111" + mail_suffix;

            void create_base_test_msg(message** msg, unsigned int to_major, unsigned int to_minor, bool is_pEp) {
                pEp_identity* from = NULL; 
                PEP_STATUS status = set_up_preset(session, JOHN, true, true, true, true, true, &from);
                ASSERT_OK;

                pEp_identity* to = NULL;
                status = set_up_preset(session, INQUISITOR, true, is_pEp, false, false, false, &to);
                ASSERT_OK;
                to->major_ver = to_major;
                to->minor_ver = to_minor;
                status = set_identity(session, to);
                ASSERT_OK;
                status = update_identity(session, to);
                ASSERT_EQ(to->major_ver, to_major);
                ASSERT_EQ(to->minor_ver, to_minor);

                message* retval = new_message(PEP_dir_outgoing);
                const char* shortmsg = "Exciting subject!";
                const char* longmsg = "¡Feliz Navidad!\n\n¡Feliz Navidad!\n\n¡Feliz Navidad, prospero año y felicidad!\n";
                retval->from = from;
                retval->to = new_identity_list(to);
                retval->shortmsg = strdup(shortmsg);
                retval->longmsg = strdup(longmsg);
                *msg = retval;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the DefaultFromEmailTest suite.


    };

}  // namespace

// Should be rerun to generate additional test mails every time the message version changes IMHO
// Add in more version strings I guess. So inelegant, but... sigh. Who has time? Not me.
// You can step through this and force some other paths to generate other paths and create emails 
// which will be otherwise difficult to get, but that shouldn't be necessary beyond the first time 
// this is written in 2.2, I suspect, so others should ignore this blathery part.
//


TEST_F(DefaultFromEmailTest, check_encrypt_to_OpenPGP_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 0, 0, false);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(OpenPGP_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_1_0_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 1, 0, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v1_0_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_2_0_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 2, 0, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v2_0_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_2_1_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 2, 1, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v2_1_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_2_2_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 2, 2, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v2_2_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_encrypt_to_pEp_10_111_simple_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    message* unenc_msg = NULL;
    message* enc_msg = NULL;
    create_base_test_msg(&unenc_msg, 10, 111, true);

    status = encrypt_message(session, unenc_msg, NULL, &enc_msg, PEP_enc_PEP, 0);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    // N.B. Actual check happens on decrypt later. But we can check that the encryption path doesn't fail, anyway.
    if (DEFAULT_FROM_TEST_GEN) {
        char* enc_text = NULL;
        status = mime_encode_message(enc_msg, false, &enc_text, false);
        ASSERT_OK;
        ASSERT_NOTNULL(enc_text);
        dump_out(v10_111_file.c_str(), enc_text);
        free(enc_text);
    }
    free_message(unenc_msg);
    free_message(enc_msg);
}

TEST_F(DefaultFromEmailTest, check_unencrypted_OpenPGP_from_TB_import_bare_default) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, PEP_OWN_USERID, "Ramoth T. Cat, Spy Queen of Orlais");
    status = myself(session, ramoth);
    ASSERT_OK;

    // FIXME: change this message to an non-expiring key, btw.
    // Import the message which contains a single key. Be sure we get this key back.
    string email = slurp("test_mails/unencrypted_OpenPGP_with_key_attached.eml");

    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    const char* sender_key_fpr = "62D4932086185C15917B72D30571AFBCA5493553";
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, enc_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* bcc = idents->ident;
    ASSERT_NOTNULL(bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // FIXME: free stuff
}

TEST_F(DefaultFromEmailTest, check_unencrypted_OpenPGP_import_default_alternate_available) {
    // PEP_STATUS status = PEP_STATUS_OK;
    // const char* sender_key_fpr = "62D4932086185C15917B72D30571AFBCA5493553";
    // pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, PEP_OWN_USERID, "Ramoth T. Cat, Spy Queen of Orlais");
    // status = myself(session, ramoth);
    // ASSERT_OK;

    // // FIXME: change this message to an non-expiring key, btw.
    // // Import the message which contains a single key. Be sure we get this key back.
    // string email = slurp("test_mails/unencrypted_OpenPGP_with_key_attached.eml");

    // ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/big_clumsy_cat_0xC6406F81_pub.asc"));
    // pEp_identity* bcc = NULL;

    // // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // // otherwise, we're also testing the parser driver.
    // message* enc_msg = NULL;
    // status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    // ASSERT_OK;
    // ASSERT_NOTNULL(enc_msg);

    // message* dec_msg = NULL;
    // stringlist_t* keylist = NULL;
    // PEP_rating rating;
    // PEP_decrypt_flags_t flags = 0;
    // status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    // ASSERT_EQ(status, PEP_UNENCRYPTED);
    // ASSERT_NULL(dec_msg);

    // identity_list* idents = NULL;
    // status = get_identities_by_address(session, enc_msg->from->address, &idents);
    // ASSERT_OK;
    // ASSERT_NOTNULL(idents);
    // ASSERT_NULL(idents->next);

    // bcc = idents->ident;
    // ASSERT_NOTNULL(bcc);
    // ASSERT_NOTNULL(bcc->fpr);
    // ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // // Now make sure update identity returns the same
    // status = update_identity(session, bcc);
    // ASSERT_NOTNULL(bcc->fpr);
    // ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // // FIXME: free stuff
}
TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_OpenPGP_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v1_import_bare_default) {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* ramoth = new_identity("ramoth_cat@darthmama.org", NULL, PEP_OWN_USERID, "Ramoth T. Cat, Spy Queen of Orlais");
    status = myself(session, ramoth);
    ASSERT_OK;

    // FIXME: change this message to an non-expiring key, btw.
    // Import the message which contains a single key. Be sure we get this key back.
    string email = slurp("test_mails/unencrypted_OpenPGP_with_key_attached.eml");

    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    const char* sender_key_fpr = "62D4932086185C15917B72D30571AFBCA5493553";
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, enc_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* bcc = idents->ident;
    ASSERT_NOTNULL(bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, bcc);
    ASSERT_NOTNULL(bcc->fpr);
    ASSERT_STREQ(sender_key_fpr, bcc->fpr);

    // FIXME: free stuff    
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_0_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_0_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_1_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_2_import_bare_default) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_2_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_OpenPGP_import_bare_default) {
    string email = slurp(OpenPGP_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = set_up_preset(session, INQUISITOR, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff    

}

TEST_F(DefaultFromEmailTest, check_OpenPGP_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v1_import_bare_default) {
    string email = slurp(v1_0_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = set_up_preset(session, INQUISITOR, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff    
}

TEST_F(DefaultFromEmailTest, check_pEp_v1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_0_import_bare_default) {
    string email = slurp(v2_0_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = set_up_preset(session, INQUISITOR, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff    
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_0_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_1_import_bare_default) {
    string email = slurp(v2_1_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = set_up_preset(session, INQUISITOR, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff        
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_1_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_2_import_bare_default) {
    string email = slurp(v2_2_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = set_up_preset(session, INQUISITOR, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff        
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_2_import_default_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v10_111_import_bare_default) {
    string email = slurp(v10_111_file);
    // We shouldn't rely on MIME_encrypt/decrypt (and should fix other tests) -
    // otherwise, we're also testing the parser driver.
    message* enc_msg = NULL;
    PEP_STATUS status = mime_decode_message(email.c_str(), email.size(), &enc_msg, NULL);
    ASSERT_OK;
    ASSERT_NOTNULL(enc_msg);

    pEp_identity* me = NULL;
    status = set_up_preset(session, INQUISITOR, true, true, true, true, true, &me);
    ASSERT_OK;

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, enc_msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    ASSERT_NOTNULL(dec_msg);

    print_mail(dec_msg);

    identity_list* idents = NULL;
    status = get_identities_by_address(session, dec_msg->from->address, &idents);
    ASSERT_OK;
    ASSERT_NOTNULL(idents);
    ASSERT_NULL(idents->next);

    pEp_identity* john = idents->ident;
    ASSERT_NOTNULL(john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // Now make sure update identity returns the same
    status = update_identity(session, john);
    ASSERT_NOTNULL(john->fpr);
    ASSERT_STREQ(john_fpr, john->fpr);

    // FIXME: free stuff        
}
/////////////////////////////////////////////////////
// The following require key election removal to function correctly
/////////////////////////////////////////////////////

TEST_F(DefaultFromEmailTest, check_unencrypted_OpenPGP_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_unencrypted_pEp_v2_2_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_OpenPGP_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_1_import_two_alternate_available) {
}

TEST_F(DefaultFromEmailTest, check_pEp_v2_2_import_two_alternate_available) {
}

