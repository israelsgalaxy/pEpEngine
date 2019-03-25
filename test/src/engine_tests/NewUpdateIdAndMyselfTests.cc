// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring> // for strcmp()
#include "TestConstants.h"

#include "pEpEngine.h"
#include "message_api.h"
#include "keymanagement.h"
#include "test_util.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "NewUpdateIdAndMyselfTests.h"

using namespace std;

NewUpdateIdAndMyselfTests::NewUpdateIdAndMyselfTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::myself_no_record_no_input_fpr"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::myself_no_record_no_input_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::myself_no_input_fpr_w_record"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::myself_no_input_fpr_w_record)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::myself_no_input_fpr_diff_user_id_w_record"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::myself_no_input_fpr_diff_user_id_w_record)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::myself_replace_fpr"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::myself_replace_fpr)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::myself_replace_fpr_revoke_key"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::myself_replace_fpr_revoke_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_username"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_username)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_new_username"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_new_username)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_only"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_use_address_username_only"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_use_address_username_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_use_address_only"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_use_address_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_use_address_only_on_own_ident"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_use_address_only_on_own_ident)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_non_existent_user_id_address"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_non_existent_user_id_address)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_address_username_userid_no_record"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_address_username_userid_no_record)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_address_username_no_record"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_address_username_no_record)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::update_identity_address_only_multiple_records"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::update_identity_address_only_multiple_records)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::key_elect_expired_key"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::key_elect_expired_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("NewUpdateIdAndMyselfTests::key_elect_only_revoked_mistrusted"),
                                                                      static_cast<Func>(&NewUpdateIdAndMyselfTests::key_elect_only_revoked_mistrusted)));
}

void NewUpdateIdAndMyselfTests::setup() {
    EngineTestSessionSuite::setup();
    if (on_test_number == 1) {
        uniqname = strdup("AAAAtestuser@testdomain.org");
        srandom(time(NULL));
        for(int i=0; i < 4;i++)
        uniqname[i] += random() & 0xf;
        
        own_user_id = get_new_uuid();
        start_username = strdup("Unser Testkandidat");
        generated_fpr = NULL;
        default_own_id = NULL;
        alias_id = NULL;
        new_fpr = NULL;
        alex_address = "pep.test.alexander@peptest.ch";
        alex_fpr = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";
        alex_userid = "Alex";
        alex_username = "SuperDuperAlex";
    }    
}

void NewUpdateIdAndMyselfTests::tear_down() {
    if (on_test_number == number_of_tests) {
        free(uniqname);
        free(own_user_id);
        free(start_username);
        free(generated_fpr);
        free(default_own_id);
        free(alias_id);
        free(new_fpr);
    }
    EngineTestSessionSuite::tear_down();
}

void NewUpdateIdAndMyselfTests::myself_no_record_no_input_fpr() {
    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity * new_me = new_identity(uniqname, NULL, own_user_id, start_username);
    
    status = myself(session, new_me);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((new_me->fpr), "new_me->fpr");
    
    generated_fpr = strdup(new_me->fpr);
    
    TEST_ASSERT_MSG((new_me->comm_type == PEP_ct_pEp), "new_me->comm_type == PEP_ct_pEp");
    
    free_identity(new_me);
}

void NewUpdateIdAndMyselfTests::myself_no_input_fpr_w_record() {
    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity* new_me = new_identity(uniqname, NULL, own_user_id, NULL);
    status = myself(session, new_me);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    
    TEST_ASSERT_MSG((new_me->fpr), "new_me->fpr");
    TEST_ASSERT_MSG((strcmp(new_me->fpr, generated_fpr) == 0), "strcmp(new_me->fpr, generated_fpr) == 0");
    TEST_ASSERT_MSG((new_me->username), "new_me->username");
    TEST_ASSERT_MSG((strcmp(new_me->username, start_username) == 0), "strcmp(new_me->username, start_username) == 0");
    TEST_ASSERT_MSG((new_me->user_id), "new_me->user_id");
    TEST_ASSERT_MSG((new_me->comm_type == PEP_ct_pEp), "new_me->comm_type == PEP_ct_pEp");
    
    default_own_id = NULL;
    status = get_userid_alias_default(session, own_user_id, &default_own_id);
    if (status == PEP_CANNOT_FIND_ALIAS) {
        // Ok, we presume our own id above is the default (should be true if there was no existing DB as in test env)
        default_own_id = strdup(own_user_id);
    }

    TEST_ASSERT_MSG((strcmp(new_me->user_id, default_own_id) == 0), "strcmp(new_me->user_id, default_own_id) == 0");
    
    cout << "PASS: myself() retrieved the correct fpr, username and default user id" << endl << endl;

    free_identity(new_me);
}

void NewUpdateIdAndMyselfTests::myself_no_input_fpr_diff_user_id_w_record() {
    PEP_STATUS status = PEP_STATUS_OK;
    alias_id = strdup("Huss Es El Mejor Presidente Del Mundo!");

    pEp_identity* new_me = new_identity(uniqname, NULL, alias_id, NULL);
    status = myself(session, new_me);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    
    TEST_ASSERT_MSG((new_me->fpr), "new_me->fpr");
    TEST_ASSERT_MSG((strcmp(new_me->fpr, generated_fpr) == 0), "strcmp(new_me->fpr, generated_fpr) == 0");
    TEST_ASSERT_MSG((new_me->username), "new_me->username");
    TEST_ASSERT_MSG((strcmp(new_me->username, start_username) == 0), "strcmp(new_me->username, start_username) == 0");
    TEST_ASSERT_MSG((new_me->user_id), "new_me->user_id");
    TEST_ASSERT_MSG((strcmp(new_me->user_id, default_own_id) == 0), "strcmp(new_me->user_id, default_own_id) == 0");
    TEST_ASSERT_MSG((new_me->comm_type == PEP_ct_pEp), "new_me->comm_type == PEP_ct_pEp");
    
    char* tmp_def = NULL;
    
    status = get_userid_alias_default(session, alias_id, &tmp_def);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((strcmp(tmp_def, default_own_id) == 0), "strcmp(tmp_def, default_own_id) == 0");

    cout << "PASS: myself() retrieved the correct fpr, username and default user id, and put the right alias in for the default";
    cout << endl << endl;
    
    free(tmp_def);
    free_identity(new_me); 
}

void NewUpdateIdAndMyselfTests::myself_replace_fpr() {
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* new_me = new_identity(uniqname, NULL, alias_id, start_username);
    status = generate_keypair(session, new_me);
    TEST_ASSERT_MSG((new_me->fpr), "new_me->fpr");
    
    cout << "Generated fingerprint ";
    cout << new_me->fpr << "\n";

    new_fpr = strdup(new_me->fpr);

    status = set_own_key(session, new_me, new_fpr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((new_me->fpr), "new_me->fpr");
    TEST_ASSERT_MSG((strcmp(new_me->fpr, generated_fpr) != 0), "strcmp(new_me->fpr, generated_fpr) != 0");
    TEST_ASSERT_MSG((strcmp(new_me->fpr, new_fpr) == 0), "strcmp(new_me->fpr, new_fpr) == 0");
    TEST_ASSERT_MSG((new_me->username), "new_me->username");
    TEST_ASSERT_MSG((strcmp(new_me->username, start_username) == 0), "strcmp(new_me->username, start_username) == 0");
    TEST_ASSERT_MSG((new_me->user_id), "new_me->user_id");
    TEST_ASSERT_MSG((strcmp(new_me->user_id, default_own_id) == 0), "strcmp(new_me->user_id, default_own_id) == 0");
    TEST_ASSERT_MSG((new_me->me), "new_me->me");
    TEST_ASSERT_MSG((new_me->comm_type == PEP_ct_pEp), "new_me->comm_type == PEP_ct_pEp");

    cout << "PASS: myself() set and retrieved the new fpr, username and default user id, and put the right alias in for the default";
    cout << endl << endl;

    // since that worked, we'll set it back as the default
    free(new_me->fpr);
    new_me->fpr = strdup(generated_fpr);
    new_me->comm_type = PEP_ct_unknown;
    status = set_own_key(session, new_me, generated_fpr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((strcmp(new_me->fpr, generated_fpr) == 0), "strcmp(new_me->fpr, generated_fpr) == 0");
    TEST_ASSERT_MSG((new_me->comm_type == PEP_ct_pEp), "new_me->comm_type == PEP_ct_pEp");    
    free_identity(new_me);
}

void NewUpdateIdAndMyselfTests::myself_replace_fpr_revoke_key() {
    PEP_STATUS status = PEP_STATUS_OK;
    status = revoke_key(session, generated_fpr, "Because it's fun");
    TEST_ASSERT (status == PEP_STATUS_OK);
    
    pEp_identity* new_me = new_identity(uniqname, NULL, alias_id, start_username);
    
    status = set_own_key(session, new_me, new_fpr);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((new_me->fpr), "new_me->fpr");
    TEST_ASSERT_MSG((strcmp(new_me->fpr, generated_fpr) != 0), "strcmp(new_me->fpr, generated_fpr) != 0");
    TEST_ASSERT_MSG((new_me->username), "new_me->username");
    TEST_ASSERT_MSG((strcmp(new_me->username, start_username) == 0), "strcmp(new_me->username, start_username) == 0");
    TEST_ASSERT_MSG((new_me->user_id), "new_me->user_id");
    TEST_ASSERT_MSG((strcmp(new_me->user_id, default_own_id) == 0), "strcmp(new_me->user_id, default_own_id) == 0");
    TEST_ASSERT_MSG((new_me->me), "new_me->me");
    TEST_ASSERT_MSG((new_me->comm_type == PEP_ct_pEp), "new_me->comm_type == PEP_ct_pEp");
    
    cout << "PASS: myself() retrieved the new fpr, username and default user id, and put the right alias in for the default";
    cout << endl << endl;
    free_identity(new_me);
}

void NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_username() {
    // 1. create original identity
    const char* alex_address = "pep.test.alexander@peptest.ch";
    const char* alex_fpr = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";
    const char* alex_userid = "Alex";
    const char* alex_username = "SuperDuperAlex";
    const string alex_pub_key = slurp("test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc");
    
    PEP_STATUS statuspub = import_key(session, alex_pub_key.c_str(), alex_pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity* alex = new_identity(alex_address, alex_fpr, alex_userid, alex_username);

    // 2. set identity
    PEP_STATUS status = set_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(alex);
            
    alex = new_identity(alex_address, NULL, alex_userid, alex_username); 
    status = update_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((alex->fpr), "alex->fpr");
    TEST_ASSERT_MSG((strcmp(alex->fpr, alex_fpr) == 0), "strcmp(alex->fpr, alex_fpr) == 0");
    TEST_ASSERT_MSG((alex->username), "alex->username");
    TEST_ASSERT_MSG((strcmp(alex->username, alex_username) == 0), "strcmp(alex->username, alex_username) == 0");
    TEST_ASSERT_MSG((alex->user_id), "alex->user_id");
    TEST_ASSERT_MSG((strcmp(alex->user_id, alex_userid) == 0), "strcmp(alex->user_id, alex_userid) == 0");
    TEST_ASSERT_MSG((!alex->me), "!alex->me"); 
    TEST_ASSERT_MSG((alex->comm_type == PEP_ct_OpenPGP_unconfirmed), "alex->comm_type == PEP_ct_OpenPGP_unconfirmed");
    TEST_ASSERT_MSG((strcmp(alex->address, alex_address) == 0), "strcmp(alex->address, alex_address) == 0");

    cout << "PASS: update_identity() correctly retrieved extant record with matching address, id, and username" << endl << endl;
    free_identity(alex);
}

void NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_new_username() {
    PEP_STATUS status = PEP_STATUS_OK;
        
    const string alex_pub_key = slurp("test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc");
    
    PEP_STATUS statuspub = import_key(session, alex_pub_key.c_str(), alex_pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity* alex = new_identity(alex_address, alex_fpr, alex_userid, alex_username);

    // 2. set identity
    status = set_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(alex);
            
    alex = new_identity(alex_address, NULL, alex_userid, alex_username); 
    status = update_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((alex->fpr), "alex->fpr");
    TEST_ASSERT_MSG((strcmp(alex->fpr, alex_fpr) == 0), "strcmp(alex->fpr, alex_fpr) == 0");
    TEST_ASSERT_MSG((alex->username), "alex->username");
    TEST_ASSERT_MSG((strcmp(alex->username, alex_username) == 0), "strcmp(alex->username, alex_username) == 0");
    TEST_ASSERT_MSG((alex->user_id), "alex->user_id");
    TEST_ASSERT_MSG((strcmp(alex->user_id, alex_userid) == 0), "strcmp(alex->user_id, alex_userid) == 0");
    TEST_ASSERT_MSG((!alex->me), "!alex->me"); 
    TEST_ASSERT_MSG((alex->comm_type == PEP_ct_OpenPGP_unconfirmed), "alex->comm_type == PEP_ct_OpenPGP_unconfirmed");
    TEST_ASSERT_MSG((strcmp(alex->address, alex_address) == 0), "strcmp(alex->address, alex_address) == 0");

    cout << "PASS: update_identity() correctly retrieved extant record with matching address, id, and username" << endl << endl;
    free_identity(alex);
}

void NewUpdateIdAndMyselfTests::update_identity_w_matching_address_user_id_only() {
    PEP_STATUS status = PEP_STATUS_OK;
    new_username = "Test Patchy";
            
    pEp_identity* alex = new_identity(alex_address, NULL, alex_userid, new_username);
    status = update_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((alex->fpr), "alex->fpr");
    TEST_ASSERT_MSG((strcmp(alex->fpr, alex_fpr) == 0), "strcmp(alex->fpr, alex_fpr) == 0");
    TEST_ASSERT_MSG((alex->username), "alex->username");
    TEST_ASSERT_MSG((strcmp(alex->username, new_username) == 0), "strcmp(alex->username, new_username) == 0");
    TEST_ASSERT_MSG((alex->user_id), "alex->user_id");
    TEST_ASSERT_MSG((strcmp(alex->user_id, alex_userid) == 0), "strcmp(alex->user_id, alex_userid) == 0");
    TEST_ASSERT_MSG((!alex->me), "!alex->me"); 
    TEST_ASSERT_MSG((alex->comm_type == PEP_ct_OpenPGP_unconfirmed), "alex->comm_type == PEP_ct_OpenPGP_unconfirmed");
    TEST_ASSERT_MSG((strcmp(alex->address, alex_address) == 0), "strcmp(alex->address, alex_address) == 0");

    free_identity(alex);
}

void NewUpdateIdAndMyselfTests::update_identity_use_address_username_only() {
    pEp_identity* alex = new_identity(alex_address, NULL, NULL, new_username); 
    PEP_STATUS status = update_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((alex->fpr), "alex->fpr");
    TEST_ASSERT_MSG((strcmp(alex->fpr, alex_fpr) == 0), "strcmp(alex->fpr, alex_fpr) == 0");
    TEST_ASSERT_MSG((alex->username), "alex->username");
    TEST_ASSERT_MSG((strcmp(alex->username, new_username) == 0), "strcmp(alex->username, new_username) == 0");
    TEST_ASSERT_MSG((alex->user_id), "alex->user_id");
    TEST_ASSERT_MSG((strcmp(alex->user_id, alex_userid) == 0), "strcmp(alex->user_id, alex_userid) == 0");
    TEST_ASSERT_MSG((!alex->me), "!alex->me"); 
    TEST_ASSERT_MSG((alex->comm_type == PEP_ct_OpenPGP_unconfirmed), "alex->comm_type == PEP_ct_OpenPGP_unconfirmed");
    TEST_ASSERT_MSG((strcmp(alex->address, alex_address) == 0), "strcmp(alex->address, alex_address) == 0");

    cout << "PASS: update_identity() correctly retrieved extant record with matching address and username" << endl << endl;
    free_identity(alex);
}

void NewUpdateIdAndMyselfTests::update_identity_use_address_only() {
    pEp_identity* alex = new_identity(alex_address, NULL, NULL, NULL); 
    PEP_STATUS status = update_identity(session, alex);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((alex->fpr), "alex->fpr");
    TEST_ASSERT_MSG((strcmp(alex->fpr, alex_fpr) == 0), "strcmp(alex->fpr, alex_fpr) == 0");
    TEST_ASSERT_MSG((alex->username), "alex->username");
    TEST_ASSERT_MSG((strcmp(alex->username, new_username) == 0), "strcmp(alex->username, new_username) == 0");
    TEST_ASSERT_MSG((alex->user_id), "alex->user_id");
    TEST_ASSERT_MSG((strcmp(alex->user_id, alex_userid) == 0), "strcmp(alex->user_id, alex_userid) == 0");
    TEST_ASSERT_MSG((!alex->me), "!alex->me"); 
    TEST_ASSERT_MSG((alex->comm_type == PEP_ct_OpenPGP_unconfirmed), "alex->comm_type == PEP_ct_OpenPGP_unconfirmed");
    TEST_ASSERT_MSG((strcmp(alex->address, alex_address) == 0), "strcmp(alex->address, alex_address) == 0");

    cout << "PASS: update_identity() correctly retrieved extant record with just matching address. Retrieved previously patched username." << endl << endl;
    free_identity(alex);
}

void NewUpdateIdAndMyselfTests::update_identity_use_address_only_on_own_ident() {
    pEp_identity* somebody = new_identity(uniqname, NULL, NULL, NULL); 
    PEP_STATUS status = update_identity(session, somebody);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    myself(session, somebody);
    TEST_ASSERT_MSG((somebody->fpr), "somebody->fpr");
    TEST_ASSERT_MSG((strcmp(somebody->fpr, new_fpr) == 0), "strcmp(somebody->fpr, new_fpr) == 0");
    TEST_ASSERT_MSG((somebody->username), "somebody->username");
    TEST_ASSERT_MSG((strcmp(somebody->username, start_username) == 0), "strcmp(somebody->username, start_username) == 0");
    TEST_ASSERT_MSG((somebody->user_id), "somebody->user_id");
    TEST_ASSERT_MSG((strcmp(somebody->user_id, default_own_id) == 0), "strcmp(somebody->user_id, default_own_id) == 0");
    TEST_ASSERT_MSG((somebody->me), "somebody->me"); // true in this case, as it was an own identity
    TEST_ASSERT_MSG((somebody->comm_type == PEP_ct_pEp), "somebody->comm_type == PEP_ct_pEp");
    TEST_ASSERT_MSG((strcmp(somebody->address, uniqname) == 0), "strcmp(somebody->address, uniqname) == 0");
    
    cout << "PASS: update_identity() retrieved the right identity information given just an address";
    cout << endl << endl;

    free_identity(somebody);
}

void NewUpdateIdAndMyselfTests::update_identity_non_existent_user_id_address() {
    pEp_identity* somebody = new_identity("nope@nope.nope", NULL, "some_user_id", NULL); 
    PEP_STATUS status = update_identity(session, somebody);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((!somebody->fpr), "!somebody->fpr");
    TEST_ASSERT_MSG((somebody->comm_type == PEP_ct_key_not_found), "somebody->comm_type == PEP_ct_key_not_found");
    
    cout << "PASS: update_identity() returns identity with no key and unknown comm type" << endl << endl;

    free_identity(somebody);
}

void NewUpdateIdAndMyselfTests::update_identity_address_username_userid_no_record() {
    const char* rando_name = "Pickley BoofBoof";
    const char* rando_userid = "Boofy";
    const char* rando_address = "boof@pickles.org";
    pEp_identity* somebody = new_identity(rando_address, NULL, rando_userid, rando_name);
    PEP_STATUS status = update_identity(session, somebody);

    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((!somebody->fpr || somebody->fpr[0] == '\0'), "!somebody->fpr || somebody->fpr[0] == '\0'");
    TEST_ASSERT_MSG((somebody->username), "somebody->username");
    TEST_ASSERT_MSG((strcmp(somebody->username, rando_name) == 0), "strcmp(somebody->username, rando_name) == 0");
    TEST_ASSERT_MSG((somebody->user_id), "somebody->user_id");
    TEST_ASSERT_MSG((strcmp(somebody->user_id, rando_userid) == 0), "strcmp(somebody->user_id, rando_userid) == 0"); // ???
    TEST_ASSERT_MSG((!somebody->me), "!somebody->me"); 
    TEST_ASSERT_MSG((somebody->comm_type == PEP_ct_key_not_found), "somebody->comm_type == PEP_ct_key_not_found");
    TEST_ASSERT_MSG((strcmp(somebody->address, rando_address) == 0), "strcmp(somebody->address, rando_address) == 0");

    cout << "PASS: update_identity() correctly created record with no key" << endl << endl;
    free_identity(somebody);
}

void NewUpdateIdAndMyselfTests::update_identity_address_username_no_record() {
    const char* rando2_name = "Pickles BoofyBoof";
    const char* rando2_address = "boof2@pickles.org";
    pEp_identity* somebody = new_identity(rando2_address, NULL, NULL, rando2_name);
    PEP_STATUS status = update_identity(session, somebody);
    const char* expected_rando2_userid = "TOFU_boof2@pickles.org";

    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((!somebody->fpr || somebody->fpr[0] == '\0'), "!somebody->fpr || somebody->fpr[0] == '\0'");
    TEST_ASSERT_MSG((somebody->username), "somebody->username");
    TEST_ASSERT_MSG((strcmp(somebody->username, rando2_name) == 0), "strcmp(somebody->username, rando2_name) == 0");
    TEST_ASSERT_MSG((somebody->user_id), "somebody->user_id");
    TEST_ASSERT_MSG((strcmp(somebody->user_id, expected_rando2_userid) == 0), "strcmp(somebody->user_id, expected_rando2_userid) == 0"); // ???
    TEST_ASSERT_MSG((!somebody->me), "!somebody->me"); 
    TEST_ASSERT_MSG((somebody->comm_type == PEP_ct_key_not_found), "somebody->comm_type == PEP_ct_key_not_found");
    TEST_ASSERT_MSG((strcmp(somebody->address, rando2_address) == 0), "strcmp(somebody->address, rando2_address) == 0");

    cout << "PASS: update_identity() correctly created record with no key" << endl << endl;
    free_identity(somebody);
}


void NewUpdateIdAndMyselfTests::update_identity_address_only_multiple_records() {
    PEP_STATUS status = PEP_STATUS_OK;
    // 1. create identity
    const char* bella_address = "pep.test.bella@peptest.ch";
    const char* bella_fpr = "5631BF1357326A02AA470EEEB815EF7FA4516AAE";
    const char* bella_userid = "TOFU_pep.test.bella@peptest.ch"; // simulate temp ID
    const char* bella_username = "Annabella the Great";
    const string bella_pub_key = slurp("test_keys/pub/pep.test.bella-0xAF516AAE_pub.asc");
    
    PEP_STATUS statuspub = import_key(session, bella_pub_key.c_str(), bella_pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity* bella = new_identity(bella_address, bella_fpr, bella_userid, bella_username);
    
    // 2. set identity
    status = set_identity(session, bella);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(bella);
    
    const char* not_my_userid = "Bad Company";
            
    bella = new_identity(bella_address, NULL, not_my_userid, bella_username); 
    status = update_identity(session, bella);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((bella->fpr), "bella->fpr");
    TEST_ASSERT_MSG((strcmp(bella->fpr, bella_fpr) == 0), "strcmp(bella->fpr, bella_fpr) == 0");
    TEST_ASSERT_MSG((bella->username), "bella->username");
    TEST_ASSERT_MSG((strcmp(bella->username, bella_username) == 0), "strcmp(bella->username, bella_username) == 0");
    TEST_ASSERT_MSG((bella->user_id), "bella->user_id");
    TEST_ASSERT_MSG((strcmp(bella->user_id, not_my_userid) == 0), "strcmp(bella->user_id, not_my_userid) == 0"); // ???
    TEST_ASSERT_MSG((!bella->me), "!bella->me"); 
    TEST_ASSERT_MSG((bella->comm_type == PEP_ct_OpenPGP_unconfirmed), "bella->comm_type == PEP_ct_OpenPGP_unconfirmed");
    TEST_ASSERT_MSG((strcmp(bella->address, bella_address) == 0), "strcmp(bella->address, bella_address) == 0");

    free_identity(bella);
    
    // ???? 
    const char* bella_id_2 = "Bella2";
    bella = new_identity(bella_address, NULL, bella_id_2, bella_username);
    
    status = set_identity(session, bella);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(bella);
                
    bella = new_identity(bella_address, NULL, NULL, NULL); 
    status = update_identity(session, bella);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

}

void NewUpdateIdAndMyselfTests::key_elect_expired_key() {
    // 1. create identity
    const char* bernd_address = "bernd.das.brot@darthmama.org";
    const char* bernd_fpr = "F8CE0F7E24EB190A2FCBFD38D4B088A7CAFAA422";
    const char* bernd_userid = "BERND_ID"; // simulate temp ID
    const char* bernd_username = "Bernd das Brot der Ultimative Testkandidat";
    const string bernd_pub_key = slurp("test_keys/pub/bernd.das.brot-0xCAFAA422_pub.asc");
    
    PEP_STATUS statuspub = import_key(session, bernd_pub_key.c_str(), bernd_pub_key.length(), NULL);
    TEST_ASSERT_MSG((statuspub == PEP_TEST_KEY_IMPORT_SUCCESS), "statuspub == PEP_STATUS_OK");

    pEp_identity* bernd = new_identity(bernd_address, bernd_fpr, bernd_userid, bernd_username);
    
    // 2. set identity
    PEP_STATUS status = set_identity(session, bernd);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    free_identity(bernd);
                
    bernd = new_identity(bernd_address, NULL, bernd_userid, bernd_username); 
    status = update_identity(session, bernd);
    TEST_ASSERT_MSG((status != PEP_STATUS_OK), "status != PEP_STATUS_OK");
    TEST_ASSERT_MSG((!bernd->fpr || bernd->fpr[0] == '\0'), "!bernd->fpr || bernd->fpr[0] == '\0'");
    TEST_ASSERT_MSG((bernd->username), "bernd->username");
    TEST_ASSERT_MSG((strcmp(bernd->username, bernd_username) == 0), "strcmp(bernd->username, bernd_username) == 0");
    TEST_ASSERT_MSG((bernd->user_id), "bernd->user_id");
    TEST_ASSERT_MSG((strcmp(bernd->user_id, bernd_userid) == 0), "strcmp(bernd->user_id, bernd_userid) == 0"); // ???
    TEST_ASSERT_MSG((!bernd->me), "!bernd->me"); 
    TEST_ASSERT_MSG((bernd->comm_type == PEP_ct_key_expired), "bernd->comm_type == PEP_ct_key_expired");
    TEST_ASSERT_MSG((strcmp(bernd->address, bernd_address) == 0), "strcmp(bernd->address, bernd_address) == 0");

    cout << "PASS: update_identity() correctly rejected expired key with PEP_KEY_UNSUITABLE and PEP_ct_key_expired" << endl << endl;
    free_identity(bernd);
    
}

void NewUpdateIdAndMyselfTests::key_elect_only_revoked_mistrusted() {
    // Create id with no key
    cout << "Creating new id with no key for : ";
    char *uniqname_10000 = strdup("AAAAtestuser@testdomain.org");
    srandom(time(NULL));
    for(int i=0; i < 4;i++)
        uniqname_10000[i] += random() & 0xf;
    
    cout << uniqname_10000 << "\n";

    char* revoke_uuid = get_new_uuid();

    pEp_identity * revokemaster_3000 = new_identity(uniqname_10000, NULL, revoke_uuid, start_username);
    
    cout << "Generate three keys for "  << uniqname_10000 << " who has user_id " << revoke_uuid << endl; 

    char* revoke_fpr_arr[3];
    
    PEP_STATUS status = generate_keypair(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK && revokemaster_3000->fpr), (string(tl_status_string(status)) + " " + revokemaster_3000->fpr).c_str());
    revoke_fpr_arr[0] = strdup(revokemaster_3000->fpr);
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = NULL;
    
    status = generate_keypair(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK && revokemaster_3000->fpr), (string(tl_status_string(status)) + " " + revokemaster_3000->fpr).c_str());
    revoke_fpr_arr[1] = strdup(revokemaster_3000->fpr);
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = NULL;
    
    status = generate_keypair(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK && revokemaster_3000->fpr), (string(tl_status_string(status)) + " " + revokemaster_3000->fpr).c_str());
    revoke_fpr_arr[2] = strdup(revokemaster_3000->fpr);
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = NULL;
    
    cout << "Trust "  << revoke_fpr_arr[2] << " (default for identity) and " << revoke_fpr_arr[0] << endl;
    
    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = strdup(revoke_fpr_arr[2]);
    status = trust_personal_key(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    status = get_trust(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((revokemaster_3000->comm_type & PEP_ct_confirmed), tl_ct_string(revokemaster_3000->comm_type));

    free(revokemaster_3000->fpr);
    revokemaster_3000->fpr = strdup(revoke_fpr_arr[0]);
    status = trust_personal_key(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    status = get_trust(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((revokemaster_3000->comm_type & PEP_ct_confirmed), tl_ct_string(revokemaster_3000->comm_type));
    
    status = update_identity(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((revokemaster_3000->fpr), revokemaster_3000->fpr);
    TEST_ASSERT_MSG((strcmp(revokemaster_3000->fpr, revoke_fpr_arr[2]) == 0), (string("Expected ") + revoke_fpr_arr[2] + ", Got " + revokemaster_3000->fpr).c_str());
    TEST_ASSERT_MSG((revokemaster_3000->comm_type & PEP_ct_confirmed), tl_ct_string(revokemaster_3000->comm_type));

    cout << "update_identity returns the correct identity default." << endl;
    
    cout << "Ok, now... we revoke the default..." << endl;
    
    cout << "Revoking " << revoke_fpr_arr[2] << endl;

    status = revoke_key(session, revoke_fpr_arr[2], "This little pubkey went to market");
    TEST_ASSERT (status == PEP_STATUS_OK);

    bool is_revoked;
    status = key_revoked(session, revokemaster_3000->fpr, &is_revoked);    
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((is_revoked), "is_revoked");

    cout << "Success revoking " << revoke_fpr_arr[2] << "!!! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;
    
    cout << "Now see if update_identity gives us " << revoke_fpr_arr[0] << ", the only trusted key left." << endl;
    status = update_identity(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((revokemaster_3000->fpr), revokemaster_3000->fpr);
    TEST_ASSERT_MSG((strcmp(revokemaster_3000->fpr, revoke_fpr_arr[0]) == 0), (string("Expected ") + revoke_fpr_arr[0] + ", Got " + revokemaster_3000->fpr).c_str());
    TEST_ASSERT_MSG((revokemaster_3000->comm_type & PEP_ct_confirmed), tl_ct_string(revokemaster_3000->comm_type));    
    
    cout << "Success! So let's mistrust it, because seriously, that key was so uncool." << endl;
    
    status = key_mistrusted(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));

    status = get_trust(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((revokemaster_3000->comm_type == PEP_ct_mistrusted), tl_ct_string(revokemaster_3000->comm_type));
    
    cout << "Success! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

    cout << "The only fpr left is an untrusted one - let's make sure this is what we get from update_identity." << endl;

    status = update_identity(session, revokemaster_3000);
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((revokemaster_3000->fpr), revokemaster_3000->fpr);
    TEST_ASSERT_MSG((strcmp(revokemaster_3000->fpr, revoke_fpr_arr[1]) == 0), (string("Expected ") + revoke_fpr_arr[1] + ", Got " + revokemaster_3000->fpr).c_str());
    TEST_ASSERT_MSG((!(revokemaster_3000->comm_type & PEP_ct_confirmed)), tl_ct_string(revokemaster_3000->comm_type));    

    cout << "Success! We got " << revoke_fpr_arr[1] << "as the fpr with comm_type " << revokemaster_3000->comm_type << endl;
    
    cout << "But, you know... let's revoke that one too and see what update_identity gives us." << endl;

    status = revoke_key(session, revoke_fpr_arr[1], "Because it's more fun to revoke ALL of someone's keys");
    TEST_ASSERT (status == PEP_STATUS_OK);

    status = key_revoked(session, revokemaster_3000->fpr, &is_revoked);    
    TEST_ASSERT_MSG((status == PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((is_revoked), "is_revoked");
    
    cout << "Success! get_trust for this fpr gives us " << revokemaster_3000->comm_type << endl;

    cout << "Call update_identity - we expect nothing, plus an error comm type." << endl;

    status = update_identity(session, revokemaster_3000);
    TEST_ASSERT_MSG((status != PEP_STATUS_OK), tl_status_string(status));
    TEST_ASSERT_MSG((!revokemaster_3000->fpr), revokemaster_3000->fpr);
    TEST_ASSERT_MSG((revokemaster_3000->username), "No revokemaster_3000->username");
    TEST_ASSERT_MSG((strcmp(revokemaster_3000->user_id, revoke_uuid) == 0), (string("Expected ") + revoke_uuid + ", Got " + revokemaster_3000->user_id).c_str());
    TEST_ASSERT_MSG((revokemaster_3000->comm_type == PEP_ct_key_not_found), tl_ct_string(revokemaster_3000->comm_type));
    cout << "Success! No key found. The comm_status error was " << revokemaster_3000->comm_type << "and the return status was " << tl_status_string(status) << endl;

    free_identity(revokemaster_3000);    
}
