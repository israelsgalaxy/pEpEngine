// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for strcmp()
#include <assert.h>
#include "blacklist.h"
#include "keymanagement.h"
#include "message_api.h"
#include "mime.h"
#include "test_util.h"

using namespace std;

int main() {
    cout << "\n*** encrypt_missing_private_key_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // blacklist test code

    cout << "blacklist only key for identity / add key / check which key is used" << endl;
    
    // B252066DE0513BECA2954F30E8E18177B28D9B9D - this is the blacklisted key in blacklisted_self.asc

    const string keytext = slurp("test_keys/priv/blacklist_self.asc");
    
    /* import it into pep */
    PEP_STATUS status7 = import_key(session, keytext.c_str(), keytext.length(), NULL);
    
    const char* bl_fpr_1 = "B252066DE0513BECA2954F30E8E18177B28D9B9D";
    bool is_blacklisted = false;
    
    pEp_identity* blacklisted_identity = new_identity("blacklistself@kgrothoff.org",
                                                      bl_fpr_1,
                                                      PEP_OWN_USERID,
                                                      "Blacklist Self");
    blacklisted_identity->me = true;
    PEP_STATUS status8 = myself(session, blacklisted_identity);
    assert (status8 == PEP_STATUS_OK);
    PEP_STATUS status9 = blacklist_add(session, bl_fpr_1);
    assert (status9 == PEP_STATUS_OK);
    PEP_STATUS status10 = blacklist_is_listed(session, bl_fpr_1, &is_blacklisted);
    assert (status10 == PEP_STATUS_OK);
    PEP_STATUS status11 = myself(session, blacklisted_identity);
    assert (status11 == PEP_STATUS_OK);

    /* identity is blacklisted. Now let's try to encrypt a message. */
    
    const char* new_key = NULL;
    
    const string mailtext = slurp("test_mails/blacklist_no_key.eml");
    
    message* tmp_msg = NULL;
    message* enc_msg = NULL;
    
    PEP_STATUS status = mime_decode_message(mailtext.c_str(), mailtext.length(), &tmp_msg);
    assert(status == PEP_STATUS_OK);
    
    
    // This isn't incoming, though... so we need to reverse the direction
    tmp_msg->dir = PEP_dir_outgoing;
    status = encrypt_message(session,
                             tmp_msg,
                             NULL,
                             &enc_msg,
                             PEP_enc_PGP_MIME,
                             0);
    assert(status == PEP_STATUS_OK);
    
//    PEP_STATUS status69 = MIME_encrypt_message(session, mailtext.c_str(), mailtext.length(), NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
//    pEp_identity * me1 = new_identity("blacklist_test@kgrothoff.org", NULL, PEP_OWN_USERID, "Blacklisted Key Message Recipient");    

    new_key = enc_msg->from->fpr;
    cout << "Encrypted with key " << new_key << endl;
    assert (strcasecmp(new_key, bl_fpr_1) != 0);
//     PEP_STATUS status = update_identity(session, me1);
//     message* msg_ptr = nullptr;
//     message* dest_msg = nullptr;
//     stringlist_t* keylist = nullptr;
//     PEP_rating rating;
//     PEP_decrypt_flags_t flags;
//     
//     status = mime_decode_message(mailtext.c_str(), mailtext.length(), &msg_ptr);
//     assert(status == PEP_STATUS_OK);
//     status = decrypt_message(session, msg_ptr, &dest_msg, &keylist, &rating, &flags);
// 
//     PEP_STATUS status12 = update_identity(session, blacklisted_identity);
// 
//     assert(strcasecmp(blacklisted_identity->fpr, new_key) == 0);
    
    status = delete_keypair(session, new_key);
    PEP_STATUS status13 = blacklist_delete(session, bl_fpr_1);
    PEP_STATUS status14 = update_identity(session, blacklisted_identity);

    free_message(tmp_msg);    
    free_message(enc_msg);
    
    cout << "calling release()\n";
    release(session);
    return 0;
}
