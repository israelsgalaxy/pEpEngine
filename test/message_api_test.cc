#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <assert.h>
#include "mime.h"
#include "message_api.h"

using namespace std;

int main() {
    cout << "\n*** message_api_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // message_api test code

    cout << "creating message…\n";
    pEp_identity * me2 = new_identity("outlooktest@dingens.org", NULL, PEP_OWN_USERID, "Outlook Test");
    // pEp_identity * me2 = new_identity("test@nokey.plop", NULL, PEP_OWN_USERID, "Test no key");
    me2->me = true;
    identity_list *to2 = new_identity_list(new_identity("vb@dingens.org", NULL, "42", "Volker Birk"));
    // identity_list *to2 = new_identity_list(new_identity("still@nokey.blup", NULL, "42", "Still no key"));
    message *msg2 = new_message(PEP_dir_outgoing);
    assert(msg2);
    msg2->from = me2;
    msg2->to = to2;
    msg2->shortmsg = strdup("hello, world");
    msg2->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
    cout << "message created.\n";

    char *text2 = nullptr;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "decrypted:\n\n";
    cout << text2 << "\n";

    free(text2);

    cout << "encrypting message as MIME multipart…\n";
    message *enc_msg2 = nullptr;
    cout << "calling encrypt_message()\n";
    status2 = encrypt_message(session, msg2, NULL, &enc_msg2, PEP_enc_PGP_MIME);
    cout << "encrypt_message() returns " << status2 << '.' << endl;
    assert(status2 == PEP_STATUS_OK);
    assert(enc_msg2);
    cout << "message encrypted.\n";
    
    status2 = mime_encode_message(enc_msg2, false, &text2);
    assert(status2 == PEP_STATUS_OK);
    assert(text2);

    cout << "encrypted:\n\n";
    cout << text2 << "\n";

    message *msg3 = nullptr;
    PEP_STATUS status3 = mime_decode_message(text2, strlen(text2), &msg3);
    assert(status3 == PEP_STATUS_OK);
    const string string3 = text2;
    //free(text2);

    unlink("msg4.asc");
    ofstream outFile3("msg4.asc");
    outFile3.write(string3.c_str(), string3.size());
    outFile3.close();

    message *msg4 = nullptr;
    stringlist_t *keylist4 = nullptr;
    PEP_color color;
    PEP_decrypt_flags_t flags;
    
    PEP_STATUS status4 = decrypt_message(session, enc_msg2, &msg4, &keylist4, &color, &flags);
    assert(status4 == PEP_STATUS_OK);
    assert(msg4);
    assert(keylist4);
    assert(color);

    cout << "keys used:";
    for (stringlist_t* kl4 = keylist4; kl4 && kl4->value; kl4 = kl4->next)
    {
        cout << " " << kl4->value;
    }
    cout << "\n\n";

    free_stringlist(keylist4);

    cout << "opening msg_no_key.asc for reading\n";
    ifstream inFile3 ("msg_no_key.asc");
    assert(inFile3.is_open());

    string text3;

    cout << "reading msg_no_key.asc sample\n";
    while (!inFile3.eof()) {
        static string line;
        getline(inFile3, line);
        text3 += line + "\r\n";
    }
    inFile3.close();

    message *msg5 = nullptr;
    PEP_STATUS status5 = mime_decode_message(text3.c_str(), text3.length(), &msg5);
    assert(status5 == PEP_STATUS_OK);

    message *msg6 = nullptr;
    stringlist_t *keylist5 = nullptr;
    PEP_color color2;
    PEP_decrypt_flags_t flags2;
    PEP_STATUS status6 = decrypt_message(session, msg5, &msg6, &keylist5, &color2, &flags2);
    assert(status6 == PEP_DECRYPT_NO_KEY);
    assert(msg6 == NULL);
    assert(keylist5 == NULL);
    assert(color2 == PEP_rating_have_no_key);
    cout << "color :" << color2 << "\n";
    free_stringlist(keylist5);

    cout << "freeing messages…\n";
    free_message(msg4);
    free_message(msg3);
    free_message(msg2);
    free_message(enc_msg2);
    free_message(msg6);
    free_message(msg5);
    cout << "done.\n";

    cout << "calling release()\n";
    release(session);
    return 0;
}
