// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "mime.h"
#include "keymanagement.h"
#include "key_reset.h"

#include "test_util.h"
#include "TestConstants.h"


#include "Engine.h"

#include <gtest/gtest.h>

PEP_STATUS KRMT_message_send_callback(message* msg);

static void* KRMT_fake_this;

//The fixture for KeyResetMessageTest
class KeyResetMessageTest : public ::testing::Test {
    public:
        Engine* engine;
        PEP_SESSION session;

        vector<message*> m_queue;
        
    protected:
                    
        const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
        const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    
        const char* alice_receive_reset_fpr = "6A349E4F68801E39145CD4C5712616A385412538";

        const string alice_user_id = PEP_OWN_USERID;
        const string bob_user_id = "BobId";
        const string carol_user_id = "carolId";
        const string dave_user_id = "DaveId";
        const string erin_user_id = "ErinErinErin";
        const string fenris_user_id = "BadWolf";

        // You can remove any or all of the following functions if its body
        // is empty.
        KeyResetMessageTest() {
            // You can do set-up work for each test here.
            test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
            test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
            test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
        }

        ~KeyResetMessageTest() override {
            // You can do clean-up work that doesn't throw exceptions here.
        }

        // If the constructor and destructor are not enough for setting up
        // and cleaning up each test, you can define the following methods:

        void SetUp() override {
            // Code here will be called immediately after the constructor (right
            // before each test).

            KRMT_fake_this = (void*)this;
            // Leave this empty if there are no files to copy to the home directory path
            std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

            // Get a new test Engine.
            engine = new Engine(test_path);
            ASSERT_NE(engine, nullptr);

            // Ok, let's initialize test directories etc.
            engine->prep(&KRMT_message_send_callback, NULL, init_files);

            // Ok, try to start this bugger.
            engine->start();
            ASSERT_NE(engine->session, nullptr);
            session = engine->session;

            // Engine is up. Keep on truckin'
            m_queue.clear();
        }

        void TearDown() override {
            // Code here will be called immediately after each test (right
            // before the destructor).
            KRMT_fake_this = NULL;            
            engine->shut_down();
            delete engine;
            engine = NULL;
            session = NULL;
        }
        
        void send_setup() {
            // Setup own identity
            PEP_STATUS status = read_file_and_import_key(session,
                        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
            assert(status == PEP_KEY_IMPORTED);
            status = set_up_ident_from_scratch(session,
                        "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                        "pep.test.alice@pep-project.org", alice_fpr,
                        alice_user_id.c_str(), "Alice in Wonderland", NULL, true
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                        "pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), "Bob's Burgers",
                        NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc",
                        "pep-test-carol@pep-project.org", NULL, carol_user_id.c_str(), "Carol Burnett",
                        NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc",
                        "pep-test-dave@pep-project.org", NULL, dave_user_id.c_str(),
                        "David Hasselhoff (Germans Love Me)", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc",
                        "pep-test-erin@pep-project.org", NULL, erin_user_id.c_str(),
                        "Éirinn go Brách", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                        "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(),
                        "Fenris Leto Hawke", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);
        }

        void receive_setup() {
            PEP_STATUS status = read_file_and_import_key(session,
                        "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
            assert(status == PEP_KEY_IMPORTED);
            status = set_up_ident_from_scratch(session,
                        "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc",
                        "pep.test.bob@pep-project.org", bob_fpr,
                        bob_user_id.c_str(), "Robert Redford", NULL, true
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                        "pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), "Alice is tired of Bob",
                        NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);
        }
        
        void create_msg_for_revoked_key() {
            PEP_STATUS status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc",
                        "pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID,
                        "Gabi", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);
            status = set_up_ident_from_scratch(session,
                        "test_keys/priv/pep-test-gabrielle-0xE203586C_priv.asc",
                        "pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID,
                        "Gabi", NULL, false
                    );
            ASSERT_EQ(status, PEP_STATUS_OK);

            status = set_up_ident_from_scratch(session,
                        "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                        "pep.test.alice@pep-project.org", NULL, "AliceOther", "Alice is tired of Bob",
                        NULL, false
                    );

            pEp_identity* from_ident = new_identity("pep-test-gabrielle@pep-project.org", NULL, PEP_OWN_USERID, NULL);
            status = myself(session, from_ident);
            ASSERT_EQ(status , PEP_STATUS_OK);
            ASSERT_NE(from_ident->fpr, nullptr);
            ASSERT_STRCASEEQ(from_ident->fpr, "906C9B8349954E82C5623C3C8C541BD4E203586C");
            ASSERT_TRUE(from_ident->me);

            // "send" some messages to update the social graph entries
            identity_list* send_idents =
                new_identity_list(
                    new_identity("pep.test.alice@pep-project.org", NULL, "AliceOther", NULL));
            status = update_identity(session, send_idents->ident);
            ASSERT_EQ(status , PEP_STATUS_OK);
            status = set_as_pEp_user(session, send_idents->ident);

            message* outgoing_msg = new_message(PEP_dir_outgoing);
            ASSERT_NE(outgoing_msg, nullptr);
            outgoing_msg->from = from_ident;
            outgoing_msg->to = send_idents;
            outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
            outgoing_msg->longmsg = strdup("Hi Mom...\n");
            outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
            output_stream << "Message created.\n\n";
            output_stream << "Encrypting message as MIME multipart…\n";
            message* enc_outgoing_msg = nullptr;
            output_stream << "Calling encrypt_message()\n";
            status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
            ASSERT_EQ(status , PEP_STATUS_OK);
            ASSERT_NE(enc_outgoing_msg, nullptr);
            output_stream << "Message encrypted.\n";
            char* outstring = NULL;
            mime_encode_message(enc_outgoing_msg, false, &outstring);
            output_stream << outstring << endl;
            free_message(enc_outgoing_msg);
            free(outstring);
        }

    private:
        const char* test_suite_name;
        const char* test_name;
        string test_path;
        // Objects declared here can be used by all tests in the KeyResetMessageTest suite.

};

PEP_STATUS KRMT_message_send_callback(message* msg) {
    ((KeyResetMessageTest*)KRMT_fake_this)->m_queue.push_back(msg);
    return PEP_STATUS_OK;
}

TEST_F(KeyResetMessageTest, check_reset_key_and_notify) {
    send_setup();

    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(from_ident->fpr, nullptr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    // "send" some messages to update the social graph entries
    identity_list* send_idents =
        new_identity_list(
            new_identity("pep.test.bob@pep-project.org",
                         NULL, bob_user_id.c_str(), "Bob's Burgers"));

    identity_list_add(send_idents, new_identity("pep-test-carol@pep-project.org", NULL, NULL, NULL));
    identity_list_add(send_idents, new_identity("pep-test-dave@pep-project.org", NULL, NULL, NULL));
    identity_list_add(send_idents, new_identity("pep-test-erin@pep-project.org", NULL, NULL, NULL));
    identity_list_add(send_idents, new_identity("pep.test.fenris@thisstilldoesntwork.lu", NULL, NULL, NULL));

    identity_list* curr_ident;

    for (curr_ident = send_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
        status = update_identity(session, curr_ident->ident);
        if (strcmp(curr_ident->ident->user_id, bob_user_id.c_str()) == 0)
            continue;

        status = set_as_pEp_user(session, curr_ident->ident);
        ASSERT_EQ(status , PEP_STATUS_OK);
    }

    output_stream << "Creating outgoing message to update DB" << endl;
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NE(outgoing_msg, nullptr);
    outgoing_msg->from = from_ident;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
    outgoing_msg->longmsg = strdup("Hi Mom...\n");
    // outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    // that's illegal - VB.
    output_stream << "Message created.\n\n";
    output_stream << "Encrypting message as MIME multipart…\n";
    message* enc_outgoing_msg = nullptr;
    output_stream << "Calling encrypt_message()\n";
    status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(enc_outgoing_msg, nullptr);
    output_stream << "Message encrypted.\n";

    // If this all worked, we should have a list of recent guys in our DB which, when we reset Alice's
    // key, will get sent some nice key reset messages.
    // But... we need to have one look like an older message. So. Time to mess with the DB.
    // Dave is our victim. Because I have a friend called Dave, who is actually a nice dude, but it amuses me.
    // (Note: said friend is NOT David Hasselhoff. To my knowledge. Hi Dave! (Addendum: Dave confirms he is
    // not Hasselhoff. But he wishes he were, sort of.))
    //
    // update identity
    //      set timestamp = 661008730
    //      where address = "pep-test-dave@pep-project.org"
    int int_result = sqlite3_exec(
        session->db,
        "update identity "
        "   set timestamp = 661008730 "
        "   where address = 'pep-test-dave@pep-project.org' ;",
        NULL,
        NULL,
        NULL
    );
    ASSERT_EQ(int_result , SQLITE_OK);

    status = key_reset(session, alice_fpr, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_GT(m_queue.size(), 0);
    status = myself(session, from_ident);
    string new_fpr = from_ident->fpr;
    ASSERT_STRNE(alice_fpr, new_fpr.c_str());

    unordered_map<string, bool> hashmap;
    hashmap[alice_user_id] = false;
    hashmap[bob_user_id] = false;
    hashmap[carol_user_id] = false;
    hashmap[dave_user_id] = false;
    hashmap[erin_user_id] = false;
    hashmap[fenris_user_id] = false;

    // Number of messages we SHOULD be sending.
    ASSERT_EQ(m_queue.size(), 4);

    for (vector<message*>::iterator it = m_queue.begin(); it != m_queue.end(); it++) {
        message* curr_sent_msg = *it;
        ASSERT_NE(curr_sent_msg, nullptr);
        ASSERT_NE(curr_sent_msg->to, nullptr);
        ASSERT_NE(curr_sent_msg->to->ident, nullptr);
        ASSERT_EQ(curr_sent_msg->to->next, nullptr);
        pEp_identity* to = curr_sent_msg->to->ident;
        ASSERT_NE(to, nullptr);
        ASSERT_NE(to->user_id, nullptr);

        unordered_map<string, bool>::iterator jt = hashmap.find(to->user_id);

        ASSERT_NE(jt, hashmap.end());
        hashmap[jt->first] = true;

        // Uncomment to regenerate received message - remember to update
        // alice_receive_reset_fpr
        // if (strcmp(curr_sent_msg->to->ident->user_id, bob_user_id.c_str()) == 0) {
        //     char* bob_msg = NULL;
        //     mime_encode_message(curr_sent_msg, false, &bob_msg);
        //     output_stream << bob_msg;
        // }
        // else if (strcmp(curr_sent_msg->to->ident->user_id, fenris_user_id.c_str()) == 0) {
        //     char* fenris_msg = NULL;
        //     mime_encode_message(curr_sent_msg, false, &fenris_msg);
        //     output_stream << fenris_msg;
        // }
    }

    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // Make sure we have messages only to desired recips
    ASSERT_FALSE(hashmap[alice_user_id]);
    ASSERT_TRUE(hashmap[bob_user_id]);
    ASSERT_TRUE(hashmap[carol_user_id]);
    ASSERT_FALSE(hashmap[dave_user_id]);
    ASSERT_TRUE(hashmap[erin_user_id]);
    ASSERT_TRUE(hashmap[fenris_user_id]);
}

TEST_F(KeyResetMessageTest, check_non_reset_receive_revoked) {
    receive_setup();
    pEp_identity* alice_ident = new_identity("pep.test.alice@pep-project.org", NULL,
                                            alice_user_id.c_str(), NULL);

    PEP_STATUS status = update_identity(session, alice_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_STREQ(alice_fpr, alice_ident->fpr);

    string received_mail = slurp("test_files/398_reset_from_alice_to_bob.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    if (keylist) // there's a test option to continue when asserts fail, so...
        ASSERT_STREQ(keylist->value,alice_receive_reset_fpr);

    status = update_identity(session, alice_ident);
    ASSERT_NE(alice_ident->fpr, nullptr);
    ASSERT_STREQ(alice_receive_reset_fpr,alice_ident->fpr);

    keylist = NULL;

    free(keylist);
}

TEST_F(KeyResetMessageTest, check_reset_receive_revoked) {
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(),
                "Fenris Leto Hawke", NULL, false
            );
    ASSERT_EQ(status, PEP_STATUS_OK);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.fenris-0x4F3D2900_priv.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(),
                "Fenris Leto Hawke", NULL, false
            );
    ASSERT_EQ(status, PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                "pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), "Alice is tired of Bob",
                NULL, false
            );
    ASSERT_EQ(status, PEP_STATUS_OK);

    pEp_identity* alice_ident = new_identity("pep.test.alice@pep-project.org", NULL,
                                            alice_user_id.c_str(), NULL);

    status = update_identity(session, alice_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_STREQ(alice_fpr, alice_ident->fpr);

    string received_mail = slurp("test_files/398_reset_from_alice_to_fenris.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(keylist, nullptr);
    if (keylist) // there's a test option to continue when asserts fail, so...
        ASSERT_STREQ(keylist->value, alice_receive_reset_fpr);

    status = update_identity(session, alice_ident);
    ASSERT_NE(alice_ident->fpr, nullptr);
    ASSERT_STREQ(alice_receive_reset_fpr, alice_ident->fpr);

    keylist = NULL;

    free(keylist);
}


TEST_F(KeyResetMessageTest, check_receive_message_to_revoked_key_from_unknown) {
    // create_msg_for_revoked_key(); // call to recreate msg
    send_setup();
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(from_ident->fpr, nullptr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    status = key_reset(session, alice_fpr, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    m_queue.clear();

    string received_mail = slurp("test_files/398_gabrielle_to_alice.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);
    ASSERT_EQ(m_queue.size() , 0);
    free(decrypted_msg);
    free(modified_src);
    free_stringlist(keylist);
    free_identity(from_ident);
}

TEST_F(KeyResetMessageTest, check_receive_message_to_revoked_key_from_contact) {
    // create_msg_for_revoked_key(); // call to recreate msg
    send_setup();
    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(from_ident->fpr, nullptr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    // Send Gabrielle a message
    identity_list* send_idents = new_identity_list(new_identity("pep-test-gabrielle@pep-project.org", NULL, "Gabi", "Gabi"));
    output_stream << "Creating outgoing message to update DB" << endl;
    message* outgoing_msg = new_message(PEP_dir_outgoing);
    ASSERT_NE(outgoing_msg, nullptr);
    outgoing_msg->from = from_ident;
    outgoing_msg->to = send_idents;
    outgoing_msg->shortmsg = strdup("Well isn't THIS a useless message...");
    outgoing_msg->longmsg = strdup("Hi Mom...\n");
    outgoing_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    output_stream << "Message created.\n\n";
    output_stream << "Encrypting message as MIME multipart…\n";
    message* enc_outgoing_msg = nullptr;
    output_stream << "Calling encrypt_message()\n";
    status = encrypt_message(session, outgoing_msg, NULL, &enc_outgoing_msg, PEP_enc_PGP_MIME, 0);
    ASSERT_EQ(status , PEP_UNENCRYPTED);
    //
    output_stream << "Message created." << endl;

    // Make the update have occurred earlier, so we don't notify her
    // (We have no key for her yet anyway!)
    int int_result = sqlite3_exec(
        session->db,
        "update identity "
        "   set timestamp = '2018-04-10 16:48:33' "
        "   where address = 'pep-test-gabrielle@pep-project.org' ;",
        NULL,
        NULL,
        NULL
    );
    ASSERT_EQ(int_result , SQLITE_OK);

    // FIXME: longer term we need to fix the test, but the key attached to the message below has expired, so for now, we give her a new key
    slurp_and_import_key(session, "test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");

    status = key_reset(session, alice_fpr, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(m_queue.size() , 0);
    m_queue.clear();

    // Now we get mail from Gabi, who only has our old key AND has become
    // a pEp user in the meantime...
    string received_mail = slurp("test_files/398_gabrielle_to_alice.eml");
    char* decrypted_msg = NULL;
    char* modified_src = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags;
    status = MIME_decrypt_message(session, received_mail.c_str(), received_mail.size(),
                                  &decrypted_msg, &keylist, &rating, &flags, &modified_src);

    ASSERT_EQ(m_queue.size() , 1);
    vector<message*>::iterator it = m_queue.begin();
    message* reset_msg = *it;
    ASSERT_NE(reset_msg, nullptr);
    ASSERT_NE(reset_msg->from, nullptr);
    ASSERT_NE(reset_msg->to, nullptr);
    ASSERT_NE(reset_msg->to->ident, nullptr);
    ASSERT_STREQ(reset_msg->to->ident->address, "pep-test-gabrielle@pep-project.org");
    ASSERT_STREQ(reset_msg->to->ident->fpr, "906C9B8349954E82C5623C3C8C541BD4E203586C");
    ASSERT_STRNE(reset_msg->from->fpr, alice_fpr);
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_STRNE(keylist->value, alice_fpr);
    ASSERT_NE(keylist->next, nullptr);
    if (strcmp(keylist->next->value, "906C9B8349954E82C5623C3C8C541BD4E203586C") != 0) {
        ASSERT_NE(keylist->next->next, nullptr);
        ASSERT_STREQ(keylist->next->value, "906C9B8349954E82C5623C3C8C541BD4E203586C");
    }
}

TEST_F(KeyResetMessageTest, check_multiple_resets_single_key) {
    send_setup();

    pEp_identity* from_ident = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    PEP_STATUS status = myself(session, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(from_ident->fpr, nullptr);
    ASSERT_STRCASEEQ(from_ident->fpr, alice_fpr);
    ASSERT_TRUE(from_ident->me);

    status = key_reset(session, NULL, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = key_reset(session, NULL, NULL);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = myself(session, from_ident);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(from_ident->fpr != NULL && from_ident->fpr[0] != 0);
}

TEST_F(KeyResetMessageTest, check_reset_ident_uid_only) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity(NULL, NULL, bob_user_id.c_str(), NULL);

    // Ok, let's reset it
    PEP_STATUS status = key_reset_identity(session, bob, NULL);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);
}

TEST_F(KeyResetMessageTest, check_reset_ident_address_only) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, NULL, NULL);

    PEP_STATUS status = key_reset_identity(session, bob, NULL);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);
}

TEST_F(KeyResetMessageTest, check_reset_ident_null_ident) {
    // Ok, let's reset it
    PEP_STATUS status = key_reset_identity(session, NULL, NULL);
    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);
}

TEST_F(KeyResetMessageTest, check_reset_ident_other_pub_fpr) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    PEP_STATUS status = update_identity(session, bob);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);

    // Ok, let's reset it
    status = key_reset_identity(session, bob, bob->fpr);
    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));
    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}

// Corner case?
TEST_F(KeyResetMessageTest, check_reset_ident_other_priv_fpr) {
    send_setup(); // lazy
    // Also import Bob's private key, because that dude is a fool.
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    status = update_identity(session, bob);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    ASSERT_FALSE(bob->me);

    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);
    ASSERT_FALSE(bob->me);

    // Ok, let's reset it
    status = key_reset_identity(session, bob, bob->fpr);
    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}

TEST_F(KeyResetMessageTest, check_reset_ident_other_pub_no_fpr) {
    send_setup(); // lazy
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    PEP_STATUS status = update_identity(session, bob);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);
    free(bob->fpr);
    bob->fpr = NULL;

    // Ok, let's reset it
    status = key_reset_identity(session, bob, NULL);
    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}
//    const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
// TODO: multiplr keys above

TEST_F(KeyResetMessageTest, check_reset_ident_other_priv_no_fpr) {
    send_setup(); // lazy
    // Also import Bob's private key, because that dude is a fool.
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), NULL);
    status = update_identity(session, bob);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(bob->fpr && bob->fpr[0]);
    status = set_as_pEp_user(session, bob);
    status = trust_personal_key(session, bob);

    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_pEp);
    ASSERT_FALSE(bob->me);
    free(bob->fpr);
    bob->fpr = NULL;

    // Ok, let's reset it
    status = key_reset_identity(session, bob, NULL);
    status = update_identity(session, bob);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(bob->comm_type , PEP_ct_key_not_found);
    ASSERT_TRUE(!(bob->fpr) || !(bob->fpr[0]));
    ASSERT_FALSE(bob->me);

    // TODO: import key, verify PEP_ct_OpenPGP_unconfirmed
}

TEST_F(KeyResetMessageTest, check_reset_ident_own_pub_fpr) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc");

    // hacky
    alice->fpr = strdup("3AD9F60FAEB22675DB873A1362D6981326B54E4E");
    status = set_pgp_keypair(session, alice->fpr);
    ASSERT_EQ(status , PEP_STATUS_OK);
    alice->comm_type = PEP_ct_OpenPGP;
    status = set_trust(session, alice);
    ASSERT_EQ(status , PEP_STATUS_OK);

    // Ok, let's reset it
    status = key_reset_identity(session, alice, alice->fpr);
    status = myself(session, alice);
    ASSERT_EQ(status , PEP_STATUS_OK);

    ASSERT_TRUE(alice->me);
    ASSERT_NE(alice->fpr, nullptr);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    ASSERT_EQ(alice->comm_type , PEP_ct_pEp);

    free(alice->fpr);
    alice->fpr = strdup("3AD9F60FAEB22675DB873A1362D6981326B54E4E");
    status = get_trust(session, alice);
    ASSERT_EQ(status , PEP_CANNOT_FIND_IDENTITY);
}

TEST_F(KeyResetMessageTest, check_reset_ident_own_priv_fpr) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(alice->fpr && alice->fpr[0]);
    ASSERT_TRUE(alice->me);
    ASSERT_STREQ(alice->fpr, alice_fpr);

    status = key_reset_identity(session, alice, alice_fpr);
    status = myself(session, alice);
    ASSERT_EQ(status , PEP_STATUS_OK);
    char* alice_new_fpr = alice->fpr;
    ASSERT_TRUE(alice_new_fpr && alice_new_fpr[0]);
    ASSERT_STRNE(alice_fpr, alice_new_fpr);
}

TEST_F(KeyResetMessageTest, check_reset_ident_own_priv_no_fpr) {
    send_setup(); // lazy
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", NULL, alice_user_id.c_str(), NULL);
    PEP_STATUS status = myself(session, alice);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_TRUE(alice->fpr && alice->fpr[0]);
    ASSERT_TRUE(alice->me);
    ASSERT_STREQ(alice->fpr, alice_fpr);
    free(alice->fpr);
    alice->fpr = NULL;
    status = key_reset_identity(session, alice, NULL);
    status = myself(session, alice);
    ASSERT_EQ(status , PEP_STATUS_OK);
    char* alice_new_fpr = alice->fpr;
    ASSERT_TRUE(alice_new_fpr && alice_new_fpr[0]);
    ASSERT_STRNE(alice_fpr, alice_new_fpr);
}

TEST_F(KeyResetMessageTest, check_reset_user_other_no_fpr) {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");

    alex_id->fpr = pubkey1;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey3;
    status = trust_personal_key(session, alex_id);
    status = set_as_pEp_user(session, alex_id);
    alex_id->fpr = pubkey4;
    status = trust_personal_key(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, NULL);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

}

TEST_F(KeyResetMessageTest, check_reset_user_other_fpr) {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");

    alex_id->fpr = pubkey1;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey3;
    status = trust_personal_key(session, alex_id);
    status = set_as_pEp_user(session, alex_id);
    alex_id->fpr = pubkey4;
    status = trust_personal_key(session, alex_id);

    status = key_reset_user(session, alex_id->user_id, pubkey3);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_GET_KEY_FAILED || !keylist || EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

TEST_F(KeyResetMessageTest, check_reset_user_own_fpr) {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    status = set_own_key(session, alex_id, pubkey3);
    status = set_own_key(session, alex_id, pubkey4);

    status = key_reset_user(session, alex_id->user_id, pubkey3);

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

TEST_F(KeyResetMessageTest, check_reset_user_no_fpr) {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    status = set_own_key(session, alex_id, pubkey3);
    status = set_own_key(session, alex_id, pubkey4);

    status = key_reset_user(session, alex_id->user_id, NULL);

    ASSERT_EQ(status , PEP_ILLEGAL_VALUE);

    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

TEST_F(KeyResetMessageTest, check_reset_all_own_keys) {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x0019697D_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0x503B14D8_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xA216E95A_priv.asc");
    status = read_file_and_import_key(session, "test_keys/priv/pep.test.alexander6-0xBDA17020_priv.asc");

    alex_id->me = true;
    status = set_own_key(session, alex_id, pubkey1);
    status = set_own_key(session, alex_id, pubkey3);
    status = set_own_key(session, alex_id, pubkey4);

    status = key_reset_all_own_keys(session);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_mistrusted);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = NULL;
    status = myself(session, alex_id);
    ASSERT_EQ(status , PEP_STATUS_OK);

    ASSERT_NE(alex_id->fpr, nullptr);
    output_stream << "alex_id->fpr is " << alex_id->fpr << endl;
    ASSERT_STRNE(alex_id->fpr, pubkey1);
    ASSERT_STRNE(alex_id->fpr, pubkey2);
    ASSERT_STRNE(alex_id->fpr, pubkey3);
    ASSERT_STRNE(alex_id->fpr, pubkey4);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_pEp);

    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);
}

TEST_F(KeyResetMessageTest, check_reset_all_own_no_own) {
      char* pubkey1 = strdup("74D79B4496E289BD8A71B70BA8E2C4530019697D");
      char* pubkey2 = strdup("2E21325D202A44BFD9C607FCF095B202503B14D8");
      char* pubkey3 = strdup("3C1E713D8519D7F907E3142D179EAA24A216E95A");
      char* pubkey4 = strdup("B4CE2F6947B6947C500F0687AEFDE530BDA17020");

      pEp_identity* alex_id = new_identity("pep.test.alexander@darthmama.org",
                                            NULL,
                                            "AlexID",
                                            "Alexander Braithwaite");

/*
test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc
test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc
test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc
test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc
*/
    PEP_STATUS status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    status = read_file_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc");

    alex_id->fpr = pubkey1;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey3;
    status = trust_personal_key(session, alex_id);
    alex_id->fpr = pubkey4;
    status = trust_personal_key(session, alex_id);

    status = key_reset_all_own_keys(session);
    ASSERT_EQ(status , PEP_CANNOT_FIND_IDENTITY);

    stringlist_t* keylist = NULL;

    alex_id->fpr = pubkey1;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_OpenPGP);
    status = find_keys(session, pubkey1, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    free_stringlist(keylist);
    keylist = NULL;

    alex_id->fpr = pubkey2;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_unknown);
    status = find_keys(session, pubkey2, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey3;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_OpenPGP);
    status = find_keys(session, pubkey3, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    alex_id->fpr = pubkey4;
    status = get_trust(session, alex_id);
    ASSERT_EQ(alex_id->comm_type , PEP_ct_OpenPGP);
    status = find_keys(session, pubkey4, &keylist);
    ASSERT_TRUE(status == PEP_STATUS_OK && keylist && !EMPTYSTR(keylist->value));

    // next line is for readability.
    alex_id->fpr = NULL;
    free_stringlist(keylist);
    free(pubkey1);
    free(pubkey2);
    free(pubkey3);
    free(pubkey4);
    free_identity(alex_id);

}