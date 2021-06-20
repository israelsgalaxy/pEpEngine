// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include "mime.h"
#include "message_api.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for TrustRatingTest
    class TrustRatingTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            // Don't clutter the global namespace
            static const char* alice_fpr; // = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
            static const char* bob_fpr; // = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";

            const char* test_suite_name;
            const char* test_name;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            TrustRatingTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~TrustRatingTest() override {
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
            string test_path;
            // Objects declared here can be used by all tests in the TrustRatingTest suite.

    };

}  // namespace

const char* TrustRatingTest::alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
const char* TrustRatingTest::bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";

static void alice_and_bob(PEP_SESSION session, pEp_identity *&alice, pEp_identity *&bob)
{
    output_stream << "\nsetting up Alice and Bob…\n";

    alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    bob = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::BOB, true, false);
    message* msg = new_message(PEP_dir_outgoing);

    output_stream << "\ndone\n";
}

TEST_F(TrustRatingTest, check_add_rating) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";

    PEP_rating sum = add_rating(PEP_rating_unreliable, PEP_rating_trusted);
    ASSERT_EQ(sum, PEP_rating_unreliable);

    sum = add_rating(PEP_rating_trusted, PEP_rating_undefined);
    ASSERT_EQ(sum, PEP_rating_undefined);
}

TEST_F(TrustRatingTest, check_rating_of_new_channel) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
 
    // rating_of_new_channel() will call update_identity()
    bob->comm_type = PEP_ct_unknown;
    free(bob->fpr);
    bob->fpr = NULL;

    PEP_rating rating;
    status = rating_of_new_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // repeat with comm_type
    rating = PEP_rating_undefined;
    status = last_rating_of_new_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // repeat without comm_type
    rating = PEP_rating_undefined;
    bob->comm_type = PEP_ct_unknown;
    status = last_rating_of_new_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");
    status = rating_of_new_channel(session, sylvia, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_have_no_key);

    // repeat
    rating = PEP_rating_undefined;
    sylvia->comm_type = PEP_ct_unknown;
    status = last_rating_of_new_channel(session, sylvia, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_have_no_key);

the_end:
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}

TEST_F(TrustRatingTest, check_rating_of_existing_channel) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    // this is calling myself(sesion, alice) and update_identity(session, bob)
    alice_and_bob(session, alice, bob);
 
    PEP_rating rating;
    status = rating_of_existing_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");
    status = update_identity(session, sylvia);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = rating_of_existing_channel(session, sylvia, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_have_no_key);

the_end:
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}

TEST_F(TrustRatingTest, check_outgoing_message_rating) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
 
    // sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");

    // outgoing message from Alice to Bob
    message *src = new_message(PEP_dir_outgoing);
    assert(src);
    src->from = identity_dup(alice);
    assert(src->from);
    src->to = new_identity_list(identity_dup(bob));
    assert(src->to && src->to->ident);

    PEP_rating rating;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);
 
    rating = PEP_rating_undefined;
    status = outgoing_message_rating_preview(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);

    // outgoing message from Alice to Sylvia
    free_identity(src->to->ident);
    src->to->ident = identity_dup(sylvia);
    assert(src->to->ident);

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
 
    rating = PEP_rating_undefined;
    status = outgoing_message_rating_preview(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    // outgoing message from Alice to Sylvia, and Bob CC
    src->cc = new_identity_list(identity_dup(bob));
    assert(src->cc && src->cc->ident);

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
 
    // outgoing message from Alice to Alice, and Bob CC
    free_identity(src->to->ident);
    src->to->ident = identity_dup(alice);
    assert(src->to->ident);

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);

    // outgoing message from Alice to Alice
    free_identity_list(src->cc);
    src->cc = nullptr;

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_trusted_and_anonymized);

the_end:
    free_message(src);
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}

/*
    Test Cases for Trust Rating of Incoming Messages

    Dramatis personae

    Alice: the own user
    Bob: Alice frequent comm partner
    Sylvia: a new comm partner of Alice

    Note: these are now marked with the status of whether or not they are covered in DefaultFromMailTest instead

    A) Handshake and TOFU

    1)  *Sylvia sends an unencrypted mail without key
        => unencrypted, no default key
        (COVERED IN DFMT)
    2)  *Sylvia sends an unencrypted mail with key attached, no claim
        *** NOTE: This just means there's more than one key attached
        => unencrypted, no default key
        (COVERED IN DFMT)
    3)  *Sylvia sends an unencrypted mail with sender key identified
        => default key set, unencrypted
        (COVERED IN DFMT)

    B) Reliable Channel to Bob

    5)  Bob sends an unencrypted mail without key
        => unencrypted
    6)  Bob sends an unencrypted mail with key attached, no claim
        *** Note: This just means there's more than one key attached
        => key imported, default key not changed, unencrypted

    X)  Bob sends an unencrypted mail with key attached, wrong claim for sender key
        *** Note: Case does not exist for unencrypted mails, no verifiable "sender"
        => b0rken
    X)  Bob sends an unencrypted mail with key attached, correct sender key
        *** Note: Case does not exist for unencrypted mails, no verifiable "sender"
        => unencrypted

    // NOTE: THESE DEPEND ON WHAT KIND OF PARTNER BOB IS AND WHAT KIND OF MESSAGES HE IS SENDING.
    //       CLAIMS ARE NOT AS CUT-AND-DRIED AS THIS OUTLINE MAKES THEM OUT TO BE
    9)  Bob sends an encrypted mail, wrong claim for sender key
        => b0rken
    10) Bob sends an encrypted mail, correct sender key but not default key
        => unreliable
    11) Bob sends an encrypted mail, correct sender key and default key
        => reliable

    C) Trustwords check between Alice and Bob was successful

    12) Bob sends an unencrypted mail without key
        => unencrypted
    13) Bob sends an unencrypted mail with key attached, no claim
        => key imported, default key not changed, unencrypted
    14) Bob sends an unencrypted mail with key attached, wrong claim for sender key
        => b0rken
    15) Bob sends an unencrypted mail with key attached, correct sender key
        => unencrypted

    16) Bob sends an encrypted mail, wrong claim for sender key
        => b0rken
    17) Bob sends an encrypted mail, correct sender key but not default key
        => unreliable
    18) Bob sends an encrypted mail, correct sender key and default key
        => trusted

*/

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
#endif

static bool default_key_set(PEP_SESSION session, pEp_identity *ident)
{
    assert(ident);

    PEP_STATUS status = update_identity(session, ident);
    assert(status == PEP_STATUS_OK);

    return !EMPTYSTR(ident->fpr);
}

// Let's please break this up - monolithic unit tests are hard to debug.

//    A) Handshake and TOFU
//    1)  Sylvia sends an unencrypted mail without key => unencrypted (no default key, but not tested here)
TEST_F(TrustRatingTest, check_incoming_message_rating_unknown_sender_no_key_unencrypted) {
    pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    ASSERT_NOTNULL(alice);

    message* incoming = string_to_msg("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted_NoKey.eml");
    ASSERT_NOTNULL(incoming);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    // Note, we're NOT testing the real thing here. This is kind of a problem. We want decrypt_and_verify,
    // and this is decrypt_message. But we'd have to replicate the entirety of _decrypt_message to
    // get all of the info we want here otherwise.
    PEP_STATUS decrypt_status = decrypt_message(session, incoming, &dec_msg, &keylist, &rating, &flags);
    ASSERT_NULL(dec_msg);
    ASSERT_NULL(keylist);
    ASSERT_EQ(decrypt_status, PEP_UNENCRYPTED);

    PEP_STATUS status = incoming_message_rating(session, incoming, dec_msg, keylist, nullptr, decrypt_status, &rating);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    free_message(incoming);
}

//    A) Handshake and TOFU
//    2) Sylvia sends an unencrypted mail with key attached, no claim
//        => unencrypted, no default key (Sylvia ***is a pEp user***, so we want the correct filename)
TEST_F(TrustRatingTest, check_incoming_message_rating_unknown_sender_no_key_unencrypted_key_bad_filename) {
    pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    ASSERT_NOTNULL(alice);

    message* incoming = string_to_msg("test_mails/test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted_wrong_key_filename.eml");
    ASSERT_NOTNULL(incoming);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    // Note, we're NOT testing the real thing here. This is kind of a problem. We want decrypt_and_verify,
    // and this is decrypt_message. But we'd have to replicate the entirety of _decrypt_message to
    // get all of the info we want here otherwise.
    PEP_STATUS decrypt_status = decrypt_message(session, incoming, &dec_msg, &keylist, &rating, &flags);
    ASSERT_NULL(dec_msg);
    ASSERT_NULL(keylist);
    ASSERT_EQ(decrypt_status, PEP_UNENCRYPTED);

    PEP_STATUS status = incoming_message_rating(session, incoming, dec_msg, keylist, nullptr, decrypt_status, &rating);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    free_message(incoming);
}

//    A) Handshake and TOFU
//    3)  Sylvia sends an unencrypted mail with sender key identified
//        => default key set (not checked here), unencrypted
TEST_F(TrustRatingTest, check_incoming_message_rating_unknown_sender_no_key_unencrypted_key_correct_filename) {
    pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    ASSERT_NOTNULL(alice);

    message* incoming = string_to_msg("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted.eml");
    ASSERT_NOTNULL(incoming);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    // Note, we're NOT testing the real thing here. This is kind of a problem. We want decrypt_and_verify,
    // and this is decrypt_message. But we'd have to replicate the entirety of _decrypt_message to
    // get all of the info we want here otherwise.
    PEP_STATUS decrypt_status = decrypt_message(session, incoming, &dec_msg, &keylist, &rating, &flags);
    ASSERT_NULL(dec_msg);
    ASSERT_NULL(keylist);
    ASSERT_EQ(decrypt_status, PEP_UNENCRYPTED);

    PEP_STATUS status = incoming_message_rating(session, incoming, dec_msg, keylist, nullptr, decrypt_status, &rating);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    free_message(incoming);
}



TEST_F(TrustRatingTest, check_incoming_message_rating) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);

    // Sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");

    // incoming message from Sylvia to Alice
    message *src = new_message(PEP_dir_incoming);
    assert(src);
    src->from = identity_dup(sylvia);
    assert(src->from);
    src->to = new_identity_list(identity_dup(alice));
    assert(src->to && src->to->ident);
    src->shortmsg = strdup("pEp");
    assert(src->shortmsg);

    PEP_rating rating = PEP_rating_undefined;

    // 1)  Sylvia sends an unencrypted mail without key

    status = incoming_message_rating(session, src, nullptr, nullptr, nullptr,
            PEP_UNENCRYPTED, &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
    ASSERT_EQ(default_key_set(session, sylvia), false);

    // 2)  Sylvia sends an unencrypted mail with key attached, no claim
    //     => unencrypted, no default key
    
    std::string sylvias_key = slurp("test_keys/pub/sylvia-pub.asc");
    src->attachments = new_bloblist(strdup(sylvias_key.c_str()), sylvias_key.size(),
            "application/pgp-keys", "sylvia-pub.asc");
    assert(src->attachments && src->attachments->value);

    status = incoming_message_rating(session, src, nullptr, nullptr, nullptr,
            PEP_UNENCRYPTED, &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
    ASSERT_EQ(default_key_set(session, sylvia), false);

    // 3)  Sylvia sends an unencrypted mail with sender key identified
    //     => default key set, unencrypted
    
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/sylvia-pub.asc"));

    stringlist_t *known_keys = new_stringlist("79CC4076D5277ED9A3123FBC7BC6B76B6BB9379B");
    assert(known_keys);

    status = incoming_message_rating(session, src, nullptr, known_keys, nullptr,
            PEP_UNENCRYPTED, &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
    ASSERT_EQ(default_key_set(session, sylvia), true);
    
the_end:
    free_stringlist(known_keys);
    free_message(src);
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}
