// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** encrypt_for_identity_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    const string alice_pub_key = slurp("test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    const string alice_priv_key = slurp("test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    const string gabrielle_pub_key = slurp("test_keys/pub/pep-test-gabrielle-0xE203586C_pub.asc");
    const string bella_pub_key = slurp("test_keys/pub/pep.test.bella-0xAF516AAE_pub.asc");    

    PEP_STATUS statuspub = import_key(session, alice_pub_key.c_str(), alice_pub_key.length(), NULL);
    PEP_STATUS statuspriv = import_key(session, alice_priv_key.c_str(), alice_priv_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    assert(statuspriv == PEP_STATUS_OK);
    
    statuspub = import_key(session, gabrielle_pub_key.c_str(), gabrielle_pub_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);
    statuspub = import_key(session, bella_pub_key.c_str(), bella_pub_key.length(), NULL);
    assert(statuspub == PEP_STATUS_OK);

    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    const char* gabrielle_fpr = "906C9B8349954E82C5623C3C8C541BD4E203586C";
    const char* bella_fpr = "5631BF1357326A02AA470EEEB815EF7FA4516AAE";
    const char* nobody_fpr = "1111111111111111111111111111111111111111";

    cout << "creating message…\n";
    pEp_identity* alice = new_identity("pep.test.alice@pep-project.org", alice_fpr, PEP_OWN_USERID, "Alice Test");
    pEp_identity* bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");
    
    alice->me = true;

    PEP_STATUS mystatus = set_own_key(session, alice, alice_fpr);
    assert(mystatus == PEP_STATUS_OK);

    identity_list* to_list = new_identity_list(bob); // to bob
    message* outgoing_message = new_message(PEP_dir_outgoing);
    assert(outgoing_message);
    outgoing_message->from = alice;
    outgoing_message->to = to_list;
    outgoing_message->shortmsg = strdup("Greetings, humans!");
    outgoing_message->longmsg = strdup("This is a test of the emergency message system. This is only a test. BEEP.");
    outgoing_message->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    char* encoded_text = nullptr;
    PEP_STATUS status = mime_encode_message(outgoing_message, false, &encoded_text);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);

    cout << "decrypted:\n\n";
    cout << encoded_text << "\n";

    free(encoded_text);

    message* encrypted_msg = nullptr;
    cout << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, NULL, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    assert(status == PEP_STATUS_OK);
    assert(encrypted_msg);
    cout << "message encrypted.\n";
    
    status = mime_encode_message(encrypted_msg, false, &encoded_text);
    assert(status == PEP_STATUS_OK);
    assert(encoded_text);

    cout << "encrypted:\n\n";
    cout << encoded_text << "\n";

    message* decoded_msg = nullptr;
    status = mime_decode_message(encoded_text, strlen(encoded_text), &decoded_msg);
    assert(status == PEP_STATUS_OK);
    const string string3 = encoded_text;

    unlink("msg_encrypt_for_self.asc");
    ofstream outFile3("msg_encrypt_for_self.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message* decrypted_msg = nullptr;
    stringlist_t* keylist_used = nullptr;

    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    assert(decrypted_msg);
    assert(keylist_used);
    assert(rating);
    assert(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    PEP_comm_type ct = encrypted_msg->from->comm_type;
    assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );

    cout << "keys used:\n";

    int i = 0;

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    {
        if (i == 0)
            assert(strcasecmp("",kl4->value) == 0);
        else {
            cout << "\t " << kl4->value << endl;
            assert(strcasecmp("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value) == 0);
            cout << "Encrypted for Alice! Yay! It worked!" << endl;
        }
        assert(i < 2);
    }
    cout << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
 
    cout << "freeing messages…\n";
    free_message(encrypted_msg);
    free_message(decrypted_msg);
    free_stringlist (keylist_used);
    cout << "done.\n";

    cout << "Now encrypt for self with extra keys." << endl;
    stringlist_t* extra_keys = new_stringlist(gabrielle_fpr);
    stringlist_add(extra_keys, bella_fpr);
    encrypted_msg = NULL;
    decrypted_msg = NULL;
    keylist_used = NULL;

    cout << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    assert(status == PEP_STATUS_OK);
    assert(encrypted_msg);
    cout << "message encrypted.\n";
    
    flags = 0;
    status = decrypt_message(session, encrypted_msg, &decrypted_msg, &keylist_used, &rating, &flags);
    assert(decrypted_msg);
    assert(keylist_used);
    assert(rating);
    assert(status == PEP_DECRYPTED && rating == PEP_rating_unreliable);
    ct = encrypted_msg->from->comm_type;
    assert(ct == PEP_ct_pEp || ct == PEP_ct_pEp_unconfirmed || ct == PEP_ct_OpenPGP || ct == PEP_ct_OpenPGP_unconfirmed );

    cout << "keys used:\n";

    for (stringlist_t* incoming_kl = extra_keys; incoming_kl && incoming_kl->value; incoming_kl = incoming_kl->next) {
        bool found = false;
        cout << "Encrypted for: ";
        for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++) {
            if (strcasecmp(incoming_kl->value, kl4->value) == 0) {
                cout << "\t " << kl4->value;
                found = true;
                break;
            }
        }
        cout << endl;
        assert(found);
    }
    cout << "Encrypted for all the extra keys!" << endl;

    bool found = false;
    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next)
    {
        if (strcasecmp(alice_fpr, kl4->value) == 0) {
            found = true;
            cout << "Encrypted also for Alice! Yay!" << endl;
            break;
        }
    }
    assert(found);

    free_message(encrypted_msg);
    encrypted_msg = NULL;
    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist_used);
    keylist_used = NULL;

    cout << "Now add a bad fpr." << endl;
    
    stringlist_add(extra_keys, nobody_fpr);
    
    cout << "calling encrypt_message_for_identity()\n";
    status = encrypt_message_for_self(session, alice, outgoing_message, extra_keys, &encrypted_msg, PEP_enc_PGP_MIME, PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    cout << "encrypt_message() returns " << std::hex << status << '.' << endl;
    assert(status != PEP_STATUS_OK);

    free_message(outgoing_message);
    outgoing_message = NULL;
    free_message(encrypted_msg);
    encrypted_msg = NULL;
    free_message(decrypted_msg);
    decrypted_msg = NULL;
    free_stringlist(keylist_used);
    keylist_used = NULL;


    cout << "*** Now testing MIME_encrypt_for_self ***" << endl;

    alice = new_identity("pep.test.alice@pep-project.org", NULL, PEP_OWN_USERID, "Alice Test");
    bob = new_identity("pep.test.bob@pep-project.org", NULL, "42", "Bob Test");

    cout << "Reading in alice_bob_encrypt_test_plaintext_mime.eml..." << endl;
    
    const string mimetext = slurp("test_mails/alice_bob_encrypt_test_plaintext_mime.eml");

    cout << "Text read:" << endl;
    cout << mimetext.c_str() << endl;
    char* encrypted_mimetext = nullptr;
    
    cout << "Calling MIME_encrypt_message_for_self" << endl;
    status = MIME_encrypt_message_for_self(session, alice, mimetext.c_str(),
                                           mimetext.size(), 
                                           NULL,
                                           &encrypted_mimetext, 
                                           PEP_enc_PGP_MIME, 
                                           PEP_encrypt_flag_force_unsigned | PEP_encrypt_flag_force_no_attached_key);
    
    cout << "Encrypted message:" << endl;
    cout << encrypted_mimetext << endl;

    cout << "Calling MIME_decrypt_message" << endl;
    
    char* decrypted_mimetext = nullptr;
    free_stringlist(keylist_used);
    keylist_used = nullptr;
    PEP_decrypt_flags_t mimeflags;
    PEP_rating mimerating;

    mimeflags = 0;
    status = MIME_decrypt_message(session,
                                  encrypted_mimetext,
                                  strlen(encrypted_mimetext),
                                  &decrypted_mimetext,
                                  &keylist_used,
                                  &mimerating,
                                  &mimeflags);

    assert(decrypted_mimetext);
    assert(keylist_used);
    assert(mimerating);
                             
    assert(status == PEP_DECRYPTED && mimerating == PEP_rating_unreliable);

    cout << "Decrypted message:" << endl;
    cout << decrypted_mimetext << endl;

    cout << "keys used:\n";

    i = 0;

    for (stringlist_t* kl4 = keylist_used; kl4 && kl4->value; kl4 = kl4->next, i++)
    {
        if (i == 0)
            assert(strcasecmp("",kl4->value) == 0);
        else {
            cout << "\t " << kl4->value << endl;
            assert(strcasecmp("4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", kl4->value) == 0);
            cout << "Encrypted for Alice! Yay! It worked!" << endl;
        }
        assert(i < 2);
    }
    cout << "Encrypted ONLY for Alice! Test passed. Move along. These are not the bugs you are looking for." << endl;
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
