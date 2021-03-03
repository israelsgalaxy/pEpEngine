#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "group.h"
#include "message_api.h"
#include "test_util.h"
#include "pEp_internal.h"

#include <gtest/gtest.h>

#define GECT_WRITEOUT 1

PEP_STATUS GECT_message_send_callback(message* msg);
PEP_STATUS GECT_ensure_passphrase_callback(PEP_SESSION session, const char* key);

static void* GECT_fake_this;

namespace {

	//The fixture for GroupEncryptionTest
    class GroupEncryptionTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            vector<message*> m_queue;
            vector<string> pass_list;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            GroupEncryptionTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~GroupEncryptionTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // yeah yeah, I played a lot of ESO over break.
            const char* manager_1_address = "fennarion@ravenwatch.house";
            const char* manager_1_name = "Fennarion of House Ravenwatch";
            const char* manager_1_fpr = "53A63A8DD7BB86C0D5D5DF92743FCA3C268B111B";
            const char* manager_1_prefix = "fennarion_0x268B111B";
            const char* manager_2_address = "vanus.galerion@mage.guild";
            const char* manager_2_name = "Vanus Galerion, the GOAT";
            const char* manager_2_fpr = "9800C0D0DCFBF7C7537E9E936A8A9FE79C875C78";
            const char* manager_2_prefix = "vanus.galerion_0x9C875C78";
            const char* member_1_address = "lyris@titanborn.skyrim";
            const char* member_1_name = "Lyris Titanborn";
            const char* member_1_fpr = "5824AAA2931821BDCDCD722F0FD5D60500E3D05A";
            const char* member_1_prefix = "lyris_0x00E3D05A";
            const char* member_2_address = "emperor@aquilarios.cyrodiil";
            const char* member_2_name = "The Prophet";
            const char* member_2_fpr = "A0FAE720349589348BD097C7B2A754FED1AC4929";
            const char* member_2_prefix = "emperor_0xD1AC4929";
            const char* member_3_address = "abner@tharn.cool";
            const char* member_3_name = "Go away, peasants!";
            const char* member_3_fpr = "39119E7972E36604F8D4C8815CC7EA7175909622";
            const char* member_3_prefix = "abner_0x75909622";
            const char* member_4_address = "sai_sahan@blades.hammerfall";
            const char* member_4_name = "Snow Lily Fan 20X6";
            const char* member_4_fpr = "1CD438E516506CCA9393933CBEFFD2F8FD070276";
            const char* member_4_prefix = "sai_sahan_0xFD070276";
            const char* group_1_address = "not_bad_vampires@ravenwatch.house";
            const char* group_1_name = "Totally Not Evil Vampires";
            const char* group_1_fpr = "1444A86CD0AEE6EA40F5C4ECDB4C2E8D0A7893F2";
            const char* group_1_prefix = "not_bad_vampires_0x0A7893F2";
            const char* group_2_address = "vanus_for_archmage@mage.guild";
            const char* group_2_name = "Vanus for Best Mage Ever Campaign";
            const char* group_2_fpr = "A39A9EE41E9D6380C8E5220E6DC64C166456E7C7";
            const char* group_2_prefix = "vanus_for_archmage_0x6456E7C7";

            string kf_name(const char* prefix, bool priv) {
                return string("test_keys/") + (priv ? "priv/" : "pub/") + prefix + (priv ? "_priv.asc" : "_pub.asc");
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).
                GECT_fake_this = (void*)this;

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(&GECT_message_send_callback, NULL, &GECT_ensure_passphrase_callback, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
                m_queue.clear();
                pass_list.clear();
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                GECT_fake_this = NULL;
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

            const char* get_prefix_from_address(const char* address) {
                if (strcmp(address, member_1_address) == 0)
                    return member_1_prefix;
                if (strcmp(address, member_2_address) == 0)
                    return member_2_prefix;
                if (strcmp(address, member_3_address) == 0)
                    return member_3_prefix;
                if (strcmp(address, member_4_address) == 0)
                    return member_4_prefix;
                return NULL;
            }


        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the GroupEncryptionTest suite.

    };

}  // namespace

PEP_STATUS GECT_message_send_callback(message* msg) {
    ((GroupEncryptionTest*)GECT_fake_this)->m_queue.push_back(msg);
    return PEP_STATUS_OK;
}

PEP_STATUS GECT_ensure_passphrase_callback(PEP_SESSION session, const char* fpr) {
    return config_valid_passphrase(session, fpr, ((GroupEncryptionTest*)GECT_fake_this)->pass_list);
}

TEST_F(GroupEncryptionTest, check_member_create_w_ident) {
    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    free_member(bob_mem);
}

TEST_F(GroupEncryptionTest, check_member_create_null_ident) {
    pEp_identity* bob = NULL;
    pEp_member* bob_mem = new_member(bob);
    ASSERT_EQ(bob_mem, nullptr);

    // Make sure this doesn't crash
    free_member(bob_mem);
}

TEST_F(GroupEncryptionTest, check_new_memberlist_w_member) {
    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* list = new_memberlist(bob_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(bob_mem, list->member);
    ASSERT_EQ(list->next, nullptr);

    free_memberlist(list);
}


TEST_F(GroupEncryptionTest, check_new_memberlist_w_null) {
    pEp_member* bob_mem = NULL;

    member_list* list = new_memberlist(bob_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(nullptr, list->member);
    ASSERT_EQ(list->next, nullptr);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_memberlist_add_to_null) {
    pEp_member* bob_mem = NULL;

    member_list* list = new_memberlist(bob_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(nullptr, list->member);
    ASSERT_EQ(list->next, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* check = memberlist_add(list, bob_mem);

    ASSERT_EQ(check, list);
    ASSERT_EQ(list->member, bob_mem);
    ASSERT_EQ(list->member->ident, bob_mem->ident);
    ASSERT_EQ(list->next, nullptr);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_memberlist_add_to_real_list) {
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", NULL);
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(carol_mem, list->member);
    ASSERT_EQ(list->next, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* check = memberlist_add(list, bob_mem);

    ASSERT_NE(nullptr, check);
    ASSERT_EQ(list->next, check);
    ASSERT_EQ(list->member, carol_mem);
    ASSERT_EQ(list->member->ident, carol);
    ASSERT_EQ(list->next->member, bob_mem);
    ASSERT_EQ(list->next->member->ident, bob);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_memberlist_add_to_list_three) {
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", NULL);
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(carol_mem, list->member);
    ASSERT_EQ(list->next, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    ASSERT_NE(bob, nullptr);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(bob_mem, nullptr);
    ASSERT_EQ(bob, bob_mem->ident);
    ASSERT_EQ(bob_mem->adopted, false);

    member_list* check = memberlist_add(list, bob_mem);
    ASSERT_NE(nullptr, check);
    
    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", NULL);
    ASSERT_NE(solas, nullptr);
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(solas_mem, nullptr);
    ASSERT_EQ(solas, solas_mem->ident);
    ASSERT_EQ(solas_mem->adopted, false);

    ASSERT_NE(check, memberlist_add(list, solas_mem));
    
    ASSERT_EQ(list->next, check);
    ASSERT_EQ(list->member, carol_mem);
    ASSERT_EQ(list->member->ident, carol);
    ASSERT_EQ(list->next->member, bob_mem);
    ASSERT_EQ(list->next->member->ident, bob);
    ASSERT_EQ(list->next->next->member, solas_mem);
    ASSERT_EQ(list->next->next->member->ident, solas);

    free_memberlist(list);
}

TEST_F(GroupEncryptionTest, check_new_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    // Create member list
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", NULL);
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(memberlist_add(list, bob_mem), nullptr);
    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", NULL);
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(memberlist_add(list, solas_mem), nullptr);

    pEp_group* group = new_group(group_ident, group_leader, list);
    ASSERT_NE(group, nullptr);
    ASSERT_EQ(group->group_identity, group_ident);
    ASSERT_EQ(group->manager, group_leader);
    ASSERT_EQ(group->members, list);

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    // Create member list
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", "Carol");
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);
    status = update_identity(session, carol);
    ASSERT_OK;

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    status = update_identity(session, bob);
    ASSERT_OK;
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(memberlist_add(list, bob_mem), nullptr);

    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", "The Dread Wolf, Betrayer of All");
    status = update_identity(session, solas);
    ASSERT_OK;
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(memberlist_add(list, solas_mem), nullptr);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, list, &group);
    ASSERT_OK;
    ASSERT_NE(group, nullptr);
    ASSERT_NE(group->group_identity, nullptr);
    ASSERT_STREQ(group->group_identity->address, group_ident->address);
    ASSERT_STREQ(group->group_identity->user_id, group_ident->user_id);
    ASSERT_NE(group->group_identity->flags & PEP_idf_group_ident, 0);
    ASSERT_NE(group->manager, nullptr);
    ASSERT_STREQ(group->manager->address, group_leader->address);
    ASSERT_STREQ(group->manager->user_id, group_leader->user_id);
    ASSERT_EQ(group->manager->flags & PEP_idf_group_ident, 0);
    ASSERT_EQ(group->members, list); // We don't do anything to this list, so....
    ASSERT_STRNE(group_ident->fpr, group_leader->fpr);

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_membership_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    // Create member list
    pEp_identity* carol = new_identity("carol@bob.bob", NULL, "CAROL_ID", "Carol");
    ASSERT_NE(carol, nullptr);
    pEp_member* carol_mem = new_member(carol);
    status = update_identity(session, carol);
    ASSERT_OK;

    member_list* list = new_memberlist(carol_mem);
    ASSERT_NE(list, nullptr);

    pEp_identity* bob = new_identity("bob@bob.bob", NULL, "BOB_ID", NULL);
    status = update_identity(session, bob);
    ASSERT_OK;
    pEp_member* bob_mem = new_member(bob);
    ASSERT_NE(memberlist_add(list, bob_mem), nullptr);

    pEp_identity* solas = new_identity("solas@solas.solas", NULL, "SOLAS_ID", "The Dread Wolf, Betrayer of All");
    status = update_identity(session, solas);
    ASSERT_OK;
    pEp_member* solas_mem = new_member(solas);
    ASSERT_NE(memberlist_add(list, solas_mem), nullptr);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, list, &group);
    ASSERT_OK;

    bool carol_found = false;
    bool solas_found = false;
    bool bob_found = false;

    member_list* retrieved_members = NULL;
    status = retrieve_full_group_membership(session, group_ident, &retrieved_members);
    ASSERT_OK;
    ASSERT_NE(retrieved_members, nullptr);

    for (member_list* curr_node = retrieved_members; curr_node && curr_node->member; curr_node = curr_node->next) {
        if (!curr_node->member->ident)
            break;
        pEp_identity* ident = curr_node->member->ident;
        if ((strcmp(ident->user_id, carol->user_id) == 0) && strcmp(ident->address, carol->address) == 0)
            carol_found = true;
        else if ((strcmp(ident->user_id, bob->user_id) == 0) && strcmp(ident->address, bob->address) == 0)
            bob_found = true;
        else if ((strcmp(ident->user_id, solas->user_id) == 0) && strcmp(ident->address, solas->address) == 0)
            solas_found = true;
        else
            ASSERT_STREQ("This message is just to make the test fail and give a message, we found an unexpected member node.", "FAIL");
        ASSERT_FALSE(curr_node->member->adopted);
    }

    ASSERT_TRUE(carol_found);
    ASSERT_TRUE(bob_found);
    ASSERT_TRUE(solas_found);

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_null_membership_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, NULL, &group);
    ASSERT_OK;

    member_list* retrieved_members = NULL;
    status = retrieve_full_group_membership(session, group_ident, &retrieved_members);
    ASSERT_OK;
    ASSERT_EQ(retrieved_members, nullptr);

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_null_manager_from_create_group) {

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    PEP_STATUS status = myself(session, group_ident);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, NULL, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_null_group_ident_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, NULL, group_leader, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_null_group_address_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    free(group_ident->address);
    group_ident->address = NULL;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_null_manager_address_from_create_group) {
    pEp_identity* group_leader = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, group_leader);
    ASSERT_OK;
    free(group_leader->address);
    group_leader->address = NULL;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;

    pEp_group* group = NULL;
    status = group_create(session, group_ident, group_leader, NULL, &group);
    ASSERT_EQ(status, PEP_ILLEGAL_VALUE);
    ASSERT_EQ(group, nullptr);
}

TEST_F(GroupEncryptionTest, check_add_invite) {
    pEp_identity* own_ident = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, own_ident);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    status = set_identity_flags(session, group_ident, group_ident->flags | PEP_idf_group_ident);
    ASSERT_OK;

    pEp_identity* manager = new_identity("bad_manager@bad.bad", NULL, "BAD_MANAGER", "bad_manager");
    status = update_identity(session, manager);
    ASSERT_OK;

    pEp_group* group = NULL;

    status = group_create(session, group_ident, manager, NULL, &group);
    ASSERT_OK;

    status = group_enable(session, group_ident);
    ASSERT_OK;

    status = add_own_membership_entry(session, group_ident, manager, own_ident);
    ASSERT_OK;

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_ident);
    ASSERT_OK;

    ASSERT_STREQ(group->manager->user_id, manager->user_id);
    ASSERT_STREQ(group->manager->address, manager->address);
    ASSERT_TRUE(group->active);
    ASSERT_FALSE(group->members->member->adopted);
    ASSERT_EQ(group->members->next, nullptr);
}

TEST_F(GroupEncryptionTest, check_join_group) {
    pEp_identity* own_ident = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, own_ident);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    status = set_identity_flags(session, group_ident, group_ident->flags | PEP_idf_group_ident);
    ASSERT_OK;

    // We'll need a key if we're to get a good response from join_group...
    const char* manager_fpr = "5B8B5FBEF04CEAA42BD7CE630E92A012F4F44414";
    status = read_file_and_import_key(session, "test_keys/pub/bad_manager_0xF4F44414_pub.asc");
    ASSERT_EQ(status, PEP_KEY_IMPORTED);
    // We should fix this above, but let's not make key election assumptions.
    pEp_identity* manager = new_identity("bad_manager@bad.bad", manager_fpr, "BAD_MANAGER", "bad_manager");
    status = set_identity(session, manager);
    ASSERT_OK;

    status = update_identity(session, manager);
    ASSERT_OK;

    pEp_group* group = NULL;

    status = group_create(session, group_ident, manager, NULL, &group);
    ASSERT_OK;

    status = group_enable(session, group_ident);
    ASSERT_OK;

    status = add_own_membership_entry(session, group_ident, manager, own_ident);
    ASSERT_OK;

    status = join_group(session, group_ident, own_ident);
    ASSERT_OK;

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_ident);
    ASSERT_OK;

    ASSERT_STREQ(group->manager->user_id, manager->user_id);
    ASSERT_STREQ(group->manager->address, manager->address);
    ASSERT_TRUE(group->active);
    ASSERT_TRUE(group->members->member->adopted);
    ASSERT_EQ(group->members->next, nullptr);

    m_queue.clear();
}

TEST_F(GroupEncryptionTest, check_join_group_no_key) {
    pEp_identity* own_ident = new_identity("alistair@lost.pants", NULL, PEP_OWN_USERID, "Alistair Theirin");
    PEP_STATUS status = myself(session, own_ident);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity("groupies@group.group", NULL, PEP_OWN_USERID, "Bad group");
    status = myself(session, group_ident);
    ASSERT_OK;
    status = set_identity_flags(session, group_ident, group_ident->flags | PEP_idf_group_ident);
    ASSERT_OK;

    pEp_identity* manager = new_identity("bad_manager@bad.bad", NULL, "BAD_MANAGER", "bad_manager");
    status = update_identity(session, manager);
    ASSERT_OK;

    pEp_group* group = NULL;

    status = group_create(session, group_ident, manager, NULL, &group);
    ASSERT_OK;

    status = group_enable(session, group_ident);
    ASSERT_OK;

    status = add_own_membership_entry(session, group_ident, manager, own_ident);
    ASSERT_OK;

    status = join_group(session, group_ident, own_ident);
    ASSERT_EQ(status, PEP_NO_TRUST);

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_ident);
    ASSERT_OK;

    ASSERT_TRUE(group->active); // ?
    ASSERT_FALSE(group->members->member->adopted);
    ASSERT_EQ(group->members->next, nullptr);

    m_queue.clear();
}

TEST_F(GroupEncryptionTest, check_protocol_group_create) {
    pEp_identity* me = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    pEp_identity* member_3 = new_identity(member_3_address, NULL, "MEMBER3", member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    status = update_identity(session, member_3);
    ASSERT_OK;
    status = set_pEp_version(session, member_3, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_3);
    ASSERT_OK;
    pEp_identity* member_4 = new_identity(member_4_address, NULL, "MEMBER4", member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    status = update_identity(session, member_4);
    ASSERT_OK;
    status = set_pEp_version(session, member_4, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_4);
    ASSERT_OK;

    member_list* new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(new_members, nullptr);
    memberlist_add(new_members, new_member(member_2));
    memberlist_add(new_members, new_member(member_3));
    memberlist_add(new_members, new_member(member_4));

    pEp_identity* group_ident = new_identity(group_1_address, NULL, PEP_OWN_USERID, group_1_name);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, me, new_members, &group);
    ASSERT_OK;

    // Ok, we now have a bunch of messages to check.
    ASSERT_EQ(m_queue.size(), 4);

    for (int i = 0; i < 4; i++) {
        message* msg = m_queue[i];
        ASSERT_NE(msg, nullptr);
        ASSERT_NE(msg->from, nullptr);
        ASSERT_NE(msg->to, nullptr);
        ASSERT_NE(msg->to->ident, nullptr);
        ASSERT_EQ(msg->to->next, nullptr);
        ASSERT_STREQ(msg->from->address, manager_1_address);

#if GECT_WRITEOUT
            char* outdata = NULL;
            mime_encode_message(msg, false, &outdata, false);
            ASSERT_NE(outdata, nullptr);
            dump_out((string("test_mails/group_create_") + get_prefix_from_address(msg->to->ident->address) + ".eml").c_str(), outdata);
            free(outdata);
#endif
    }


    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // FIXME: Check all of the DB stuff, etc
    // Ok, now let's see what's inside the box
    pEp_group* group_info = NULL;
    status = retrieve_group_info(session, group_ident, &group_info);
    ASSERT_OK;
    ASSERT_NE(group_info, nullptr);

    ASSERT_NE(group_info->group_identity, nullptr);
    ASSERT_STREQ(group_ident->address, group_info->group_identity->address);
    ASSERT_STREQ(group_ident->user_id, group_info->group_identity->user_id);

    ASSERT_NE(group_info->manager, nullptr);
    ASSERT_STREQ(group_info->manager->user_id, me->user_id);
    ASSERT_STREQ(group_info->manager->address, me->address);

    status = myself(session, group_info->manager);
    ASSERT_OK;
    ASSERT_NE(group_info->manager->fpr, nullptr);
    ASSERT_STREQ(group_info->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group_info->manager->username, me->username);
    ASSERT_STREQ(group_info->manager->username, manager_1_name);

    ASSERT_TRUE(group_info->active);

    // Ok, time to check the member list. Tricky...
    const char* member_names[] = {member_1_name, member_2_name, member_3_name, member_4_name};
    const char* member_addrs[] = {member_1_address, member_2_address, member_3_address, member_4_address};
    const char* member_fprs[] = {member_1_fpr, member_2_fpr, member_3_fpr, member_4_fpr};

    bool found[] = {false, false, false, false};

    int count = 0;
    for (member_list* curr_member = group_info->members;
            curr_member && curr_member->member && curr_member->member->ident;
            curr_member = curr_member->next) {

        pEp_member* memb = curr_member->member;
        pEp_identity* ident = memb->ident;
        const char* userid = ident->user_id;
        const char* address = ident->address;
        ASSERT_NE(userid, nullptr);
        ASSERT_NE(address, nullptr);

        status = update_identity(session, ident);
        ASSERT_OK;

        const char* fpr = ident->fpr;
        const char* name = ident->username;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);

        ASSERT_FALSE(memb->adopted);

        int index = -1;

        for (int i = 0; i < 4; i++) {
            if (strcmp(member_names[i], name) == 0) {
                index = i;
                break;
            }
        }
        ASSERT_GT(index, -1);
        ASSERT_LT(index, 5);
        ASSERT_STREQ(member_addrs[index], address);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;
        count++;
    }

    ASSERT_EQ(count, 4);
    for (int i = 0; i < 4; i++) {
        ASSERT_TRUE(found[i]);
    }

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_1) {
    const char* own_id = "DIFFERENT_OWN_ID_FOR_KICKS";
    pEp_identity* me = new_identity(member_1_address, NULL, own_id, member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_1_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_1_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_1_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    ASSERT_STRNE(group_identity->user_id, PEP_OWN_USERID);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_1_name);
    ASSERT_STREQ(msg->to->ident->address, member_1_address);

    // Ok, now let's see what's inside the box
    pEp_group* group_info = NULL;
    status = retrieve_group_info(session, group_identity, &group_info);
    ASSERT_OK;
    ASSERT_NE(group_info, nullptr);

    ASSERT_NE(group_info->group_identity, nullptr);
    ASSERT_STREQ(group_identity->address, group_info->group_identity->address);
    ASSERT_STREQ(group_identity->user_id, group_info->group_identity->user_id);

    ASSERT_NE(group_info->manager, nullptr);
    ASSERT_STREQ(group_info->manager->user_id, manager->user_id);
    ASSERT_STREQ(group_info->manager->address, manager->address);
    ASSERT_STREQ(group_info->manager->user_id, manager->user_id);

    status = update_identity(session, group_info->manager);
    ASSERT_OK;
    ASSERT_NE(group_info->manager->fpr, nullptr);
    ASSERT_STREQ(group_info->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group_info->manager->username, manager->username);
    ASSERT_STREQ(group_info->manager->username, manager_1_name);

    // Are all non-mine groups are "inactive" (meaning it doesn't mean anything), or
    // they stay inactive until I am an active member? Ask vb. I think it's meaningless on
    // This end, but it appears we make it true when we create the group. Hmmm.
    // ASSERT_FALSE(group_info->active);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_2) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_2_address, NULL, own_id, member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_2_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_2_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_2_name);
    ASSERT_STREQ(msg->to->ident->address, member_2_address);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_3) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_3_address, NULL, own_id, member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_3_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_3_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_3_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_3_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_3_name);
    ASSERT_STREQ(msg->to->ident->address, member_3_address);
}

TEST_F(GroupEncryptionTest, check_protocol_group_create_receive_member_4) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_4_address, NULL, own_id, member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_4_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_4_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_4_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_") + member_4_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Let's see if the message did the right thing:
    pEp_identity* group_identity = new_identity(group_1_address, NULL, NULL, NULL);
    status = update_identity(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    // FIXME: Uncomment after ENGINE-878 is resolved
    //    ASSERT_STREQ(group_identity->username, group_1_name);
    pEp_identity* manager = new_identity(manager_1_address, NULL, NULL, NULL);
    status = update_identity(session, manager);
    ASSERT_OK;
    ASSERT_TRUE(!is_me(session, manager));
    ASSERT_EQ(manager->flags & PEP_idf_group_ident, 0);
    if (!is_me(session, msg->to->ident)) {
        status = update_identity(session, msg->to->ident);
        ASSERT_OK;
    }
    ASSERT_TRUE(is_me(session,msg->to->ident));
    ASSERT_STREQ(msg->to->ident->username, member_4_name);
    ASSERT_STREQ(msg->to->ident->address, member_4_address);
}

// Redundant, but we need this for various fun and games - we need a group key that
// stays consistent so we can check later protocol steps.
TEST_F(GroupEncryptionTest, check_protocol_group_create_extant_key) {
    pEp_identity* me = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity(group_1_address, group_1_fpr, PEP_OWN_USERID, group_1_name);
    read_file_and_import_key(session, kf_name(group_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_1_prefix, true).c_str());
    status = set_own_key(session, group_ident, group_1_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    pEp_identity* member_3 = new_identity(member_3_address, NULL, "MEMBER3", member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    status = update_identity(session, member_3);
    ASSERT_OK;
    status = set_pEp_version(session, member_3, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_3);
    ASSERT_OK;
    pEp_identity* member_4 = new_identity(member_4_address, NULL, "MEMBER4", member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    status = update_identity(session, member_4);
    ASSERT_OK;
    status = set_pEp_version(session, member_4, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_4);
    ASSERT_OK;

    member_list* new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(new_members, nullptr);
    memberlist_add(new_members, new_member(member_2));
    memberlist_add(new_members, new_member(member_3));
    memberlist_add(new_members, new_member(member_4));

    pEp_group* group = NULL;
    status = group_create(session, group_ident, me, new_members, &group);
    ASSERT_OK;

    ASSERT_STREQ(group->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group->group_identity->fpr, group_1_fpr);

    // Ok, we now have a bunch of messages to check.
    ASSERT_EQ(m_queue.size(), 4);

    for (int i = 0; i < 4; i++) {
        message* msg = m_queue[i];
        ASSERT_NE(msg, nullptr);
        ASSERT_NE(msg->from, nullptr);
        ASSERT_NE(msg->to, nullptr);
        ASSERT_NE(msg->to->ident, nullptr);
        ASSERT_EQ(msg->to->next, nullptr);
        ASSERT_STREQ(msg->from->address, manager_1_address);

#if GECT_WRITEOUT
            char* outdata = NULL;
            mime_encode_message(msg, false, &outdata, false);
            ASSERT_NE(outdata, nullptr);
            dump_out((string("test_mails/group_create_extant_key_") + get_prefix_from_address(msg->to->ident->address) + ".eml").c_str(), outdata);
            free(outdata);
#endif
    }

    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // FIXME: Check all of the DB stuff, etc
    // Ok, now let's see what's inside the box
    pEp_group* group_info = NULL;
    status = retrieve_group_info(session, group_ident, &group_info);
    ASSERT_OK;
    ASSERT_NE(group_info, nullptr);

    ASSERT_NE(group_info->group_identity, nullptr);
    ASSERT_STREQ(group_ident->address, group_info->group_identity->address);
    ASSERT_STREQ(group_ident->user_id, group_info->group_identity->user_id);

    ASSERT_NE(group_info->manager, nullptr);
    ASSERT_STREQ(group_info->manager->user_id, me->user_id);
    ASSERT_STREQ(group_info->manager->address, me->address);

    status = myself(session, group_info->manager);
    ASSERT_OK;
    ASSERT_NE(group_info->manager->fpr, nullptr);
    ASSERT_STREQ(group_info->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group_info->manager->username, me->username);
    ASSERT_STREQ(group_info->manager->username, manager_1_name);

    ASSERT_TRUE(group_info->active);

    // Ok, time to check the member list. Tricky...
    const char* member_names[] = {member_1_name, member_2_name, member_3_name, member_4_name};
    const char* member_addrs[] = {member_1_address, member_2_address, member_3_address, member_4_address};
    const char* member_fprs[] = {member_1_fpr, member_2_fpr, member_3_fpr, member_4_fpr};

    bool found[] = {false, false, false, false};

    int count = 0;
    for (member_list* curr_member = group_info->members;
            curr_member && curr_member->member && curr_member->member->ident;
            curr_member = curr_member->next) {

        pEp_member* memb = curr_member->member;
        pEp_identity* ident = memb->ident;
        const char* userid = ident->user_id;
        const char* address = ident->address;
        ASSERT_NE(userid, nullptr);
        ASSERT_NE(address, nullptr);

        status = update_identity(session, ident);
        ASSERT_OK;

        const char* fpr = ident->fpr;
        const char* name = ident->username;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);

        ASSERT_FALSE(memb->adopted);

        int index = -1;

        for (int i = 0; i < 4; i++) {
            if (strcmp(member_names[i], name) == 0) {
                index = i;
                break;
            }
        }
        ASSERT_GT(index, -1);
        ASSERT_LT(index, 5);
        ASSERT_STREQ(member_addrs[index], address);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;
        count++;
    }

    ASSERT_EQ(count, 4);
    for (int i = 0; i < 4; i++) {
        ASSERT_TRUE(found[i]);
    }

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_protocol_join_group_member_1) {
    const char* own_id = "DIFFERENT_OWN_ID_FOR_KICKS";
    pEp_identity* me = new_identity(member_1_address, NULL, own_id, member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_1_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_1_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_extant_key_") + member_1_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    pEp_identity* group_identity = new_identity(group_1_address, NULL, own_id, NULL);
    status = myself(session, group_identity);
    ASSERT_OK;
    ASSERT_TRUE(is_me(session, group_identity));
    ASSERT_NE(group_identity->flags & PEP_idf_group_ident, 0);
    ASSERT_STREQ(group_identity->fpr, group_1_fpr);

    pEp_group* group = new_group(group_identity, NULL, NULL);
    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    ASSERT_FALSE(group->members->member->adopted);

    // Ok, we know groups get created or other tests above would fail. Let's accept
    // the request

    status = join_group(session, group_identity, me);
    ASSERT_OK;

    ASSERT_EQ(m_queue.size(), 1);

    msg = m_queue[0];
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg->from, nullptr);
    ASSERT_NE(msg->to, nullptr);
    ASSERT_NE(msg->to->ident, nullptr);
    ASSERT_EQ(msg->to->next, nullptr);
    ASSERT_STREQ(msg->from->address, member_1_address);
    ASSERT_STREQ(msg->to->ident->address, manager_1_address);

#if GECT_WRITEOUT
    char* outdata = NULL;
    mime_encode_message(msg, false, &outdata, false);
    ASSERT_NE(outdata, nullptr);
    dump_out((string("test_mails/group_join_") + member_1_prefix + ".eml").c_str(), outdata);
    free(outdata);
#endif

    m_queue.clear();

    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    ASSERT_TRUE(group->members->member->adopted);
}

TEST_F(GroupEncryptionTest, join_group_member_2) {
    const char* own_id = "PEP_OWN_USERID"; // on purpose, little joke here
    pEp_identity* me = new_identity(member_2_address, NULL, own_id, member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_2_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_2_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_extant_key_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    pEp_identity* group_identity = new_identity(group_1_address, NULL, own_id, NULL);
    status = myself(session, group_identity);
    pEp_group* group = new_group(group_identity, NULL, NULL);
    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    status = join_group(session, group_identity, me);
    ASSERT_OK;

    ASSERT_EQ(m_queue.size(), 1);

    msg = m_queue[0];
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg->from, nullptr);
    ASSERT_NE(msg->to, nullptr);
    ASSERT_NE(msg->to->ident, nullptr);
    ASSERT_EQ(msg->to->next, nullptr);
    ASSERT_STREQ(msg->from->address, member_2_address);
    ASSERT_STREQ(msg->to->ident->address, manager_1_address);

#if GECT_WRITEOUT
    char* outdata = NULL;
    mime_encode_message(msg, false, &outdata, false);
    ASSERT_NE(outdata, nullptr);
    dump_out((string("test_mails/group_join_") + member_2_prefix + ".eml").c_str(), outdata);
    free(outdata);
#endif

    m_queue.clear();
}

TEST_F(GroupEncryptionTest, join_group_member_3) {
    const char* own_id = "BAH";
    pEp_identity* me = new_identity(member_3_address, NULL, own_id, member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_3_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_3_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_3_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_extant_key_") + member_3_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    pEp_identity* group_identity = new_identity(group_1_address, NULL, own_id, NULL);
    status = myself(session, group_identity);
    pEp_group* group = new_group(group_identity, NULL, NULL);
    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    status = join_group(session, group_identity, me);
    ASSERT_OK;

    ASSERT_EQ(m_queue.size(), 1);

    msg = m_queue[0];
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg->from, nullptr);
    ASSERT_NE(msg->to, nullptr);
    ASSERT_NE(msg->to->ident, nullptr);
    ASSERT_EQ(msg->to->next, nullptr);
    ASSERT_STREQ(msg->from->address, member_3_address);
    ASSERT_STREQ(msg->to->ident->address, manager_1_address);

#if GECT_WRITEOUT
    char* outdata = NULL;
    mime_encode_message(msg, false, &outdata, false);
    ASSERT_NE(outdata, nullptr);
    dump_out((string("test_mails/group_join_") + member_3_prefix + ".eml").c_str(), outdata);
    free(outdata);
#endif

    m_queue.clear();
}

TEST_F(GroupEncryptionTest, join_group_member_4) {
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_4_address, NULL, own_id, member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_4_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_4_fpr);
    ASSERT_OK;

    status = myself(session, me);

    ASSERT_STREQ(me->fpr, member_4_fpr);

    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    string msg_str = slurp(string("test_mails/group_create_extant_key_") + member_4_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    pEp_identity* group_identity = new_identity(group_1_address, NULL, own_id, NULL);
    status = myself(session, group_identity);
    pEp_group* group = new_group(group_identity, NULL, NULL);
    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    status = join_group(session, group_identity, me);
    ASSERT_OK;

    ASSERT_EQ(m_queue.size(), 1);

    msg = m_queue[0];
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg->from, nullptr);
    ASSERT_NE(msg->to, nullptr);
    ASSERT_NE(msg->to->ident, nullptr);
    ASSERT_EQ(msg->to->next, nullptr);
    ASSERT_STREQ(msg->from->address, member_4_address);
    ASSERT_STREQ(msg->to->ident->address, manager_1_address);

#if GECT_WRITEOUT
    char* outdata = NULL;
    mime_encode_message(msg, false, &outdata, false);
    ASSERT_NE(outdata, nullptr);
    dump_out((string("test_mails/group_join_") + member_4_prefix + ".eml").c_str(), outdata);
    free(outdata);
#endif

    m_queue.clear();
}


TEST_F(GroupEncryptionTest, check_protocol_join_group_receive) {

    // We have to replicate the whole group creation business in order to receive the message.
    pEp_identity* me = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity(group_1_address, group_1_fpr, PEP_OWN_USERID, group_1_name);
    read_file_and_import_key(session, kf_name(group_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_1_prefix, true).c_str());
    status = set_own_key(session, group_ident, group_1_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;

    member_list* new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(new_members, nullptr);

    pEp_group* group = NULL;
    status = group_create(session, group_ident, me, new_members, &group);
    ASSERT_OK;

    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // Make sure they aren't an active part of the group.
    free_group(group);
    group = NULL;

    // We lose ownership of group_ident here - maybe we shouldn't?
    status = retrieve_group_info(session, group_ident, &group);
    ASSERT_NE(group, nullptr);
    ASSERT_NE(group->members, nullptr);
    ASSERT_NE(group->members->member, nullptr);
    ASSERT_NE(group->members->member->ident, nullptr);
    ASSERT_EQ(group->members->next, nullptr);
    ASSERT_STREQ(group->members->member->ident->user_id, "MEMBER1");
    ASSERT_STREQ(group->members->member->ident->address, member_1_address);
    ASSERT_FALSE(group->members->member->adopted);
    free_group(group);
    group = NULL;

    // Ok, group exists. Now... let's get the "response email"
    string msg_str = slurp(string("test_mails/group_join_") + member_1_prefix + ".eml");
    message* msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Ok, so that worked.
    stringpair_list_t* autoconsume = stringpair_list_find(msg->opt_fields, "pEp-auto-consume");
    ASSERT_NE(autoconsume, nullptr);

    // Now let's see if our friend is part of the group.
    status = retrieve_group_info(session, group_ident, &group);
    ASSERT_NE(group, nullptr);
    ASSERT_NE(group->members, nullptr);
    ASSERT_NE(group->members->member, nullptr);
    ASSERT_NE(group->members->member->ident, nullptr);
    ASSERT_EQ(group->members->next, nullptr);
    ASSERT_STREQ(group->members->member->ident->user_id, "MEMBER1");
    ASSERT_STREQ(group->members->member->ident->address, member_1_address);
    ASSERT_TRUE(group->members->member->adopted);

    // HOORAY.
}

TEST_F(GroupEncryptionTest, check_protocol_group_dissolve_send) {
    pEp_identity* me = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity(group_1_address, group_1_fpr, PEP_OWN_USERID, group_1_name);
    read_file_and_import_key(session, kf_name(group_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_1_prefix, true).c_str());
    status = set_own_key(session, group_ident, group_1_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    pEp_identity* member_3 = new_identity(member_3_address, NULL, "MEMBER3", member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    status = update_identity(session, member_3);
    ASSERT_OK;
    status = set_pEp_version(session, member_3, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_3);
    ASSERT_OK;
    pEp_identity* member_4 = new_identity(member_4_address, NULL, "MEMBER4", member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    status = update_identity(session, member_4);
    ASSERT_OK;
    status = set_pEp_version(session, member_4, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_4);
    ASSERT_OK;

    member_list* new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(new_members, nullptr);
    memberlist_add(new_members, new_member(member_2));
    memberlist_add(new_members, new_member(member_3));
    memberlist_add(new_members, new_member(member_4));

    pEp_group* group = NULL;
    status = group_create(session, group_ident, me, new_members, &group);
    ASSERT_OK;

    // Ok, so we've actually already got the messages for this written out elsewhere - this was all DB setup.
    // Let's move on to importing the acceptances - we'll decide only three are going to accept - and then
    // dissolving the group.
    m_queue.clear();

    // Get mails - out of order, just because
    // Member 4
    string msg_str = slurp(string("test_mails/group_join_") + member_4_prefix + ".eml");
    message* msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Member 1
    msg_str = slurp(string("test_mails/group_join_") + member_1_prefix + ".eml");
    free_message(msg);
    msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    free_message(dec_msg);
    dec_msg = NULL;
    free_stringlist(keylist);
    keylist = NULL;
    rating = PEP_rating_undefined;
    flags = 0;
    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Member 2
    msg_str = slurp(string("test_mails/group_join_") + member_2_prefix + ".eml");
    free_message(msg);
    msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    free_message(dec_msg);
    dec_msg = NULL;
    free_stringlist(keylist);
    keylist = NULL;
    rating = PEP_rating_undefined;
    flags = 0;
    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;
    
    free_message(msg);
    msg = NULL;
    free_message(dec_msg);
    dec_msg = NULL;
    free_stringlist(keylist);
    keylist = NULL;

    // Ok, we've now got acceptances from member 1, member 2, and member 4.

    // First, make sure that's who's in our group, eh?
    member_list* members = NULL;
    status = retrieve_active_member_list(session, group_ident, &members);
    const char* member_names[] = {member_1_name, member_2_name, member_4_name};
    const char* member_addrs[] = {member_1_address, member_2_address, member_4_address};
    const char* member_fprs[] = {member_1_fpr, member_2_fpr, member_4_fpr};
    const char* member_prefixes[] = {member_1_prefix, member_2_prefix, member_4_prefix};

    bool found[] = {false, false, false};

    int count = 0;
    for (member_list* curr_member = members;
            curr_member && curr_member->member && curr_member->member->ident;
            curr_member = curr_member->next) {

        pEp_member* memb = curr_member->member;
        pEp_identity* ident = memb->ident;
        const char* userid = ident->user_id;
        const char* address = ident->address;
        ASSERT_NE(userid, nullptr);
        ASSERT_NE(address, nullptr);

        status = update_identity(session, ident);
        ASSERT_OK;

        const char* fpr = ident->fpr;
        const char* name = ident->username;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);

        ASSERT_TRUE(memb->adopted);

        int index = -1;

        for (int i = 0; i < 3; i++) {
            if (strcmp(member_names[i], name) == 0) {
                index = i;
                break;
            }
        }
        ASSERT_GT(index, -1);
        ASSERT_LT(index, 4);
        ASSERT_STREQ(member_addrs[index], address);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;
        count++;
    }
    ASSERT_EQ(count, 3);
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(found[i]);
    }

    // Ok, group has all the members. Now we can dissolve the group.
    m_queue.clear(); // Just in case

    status = group_dissolve(session, group_ident, me);
    ASSERT_OK;

    member_list* list = NULL;
    status = retrieve_active_member_list(session, group_ident, &list);
    ASSERT_EQ(list, nullptr);
    ASSERT_OK;

    ASSERT_EQ(m_queue.size(), 3);

    // Make sure we sent them to the right people:
    for (int i = 0; i < 3; i++)
        found[i] = false;

    for (count = 0; count < 3; count++) {
        msg = m_queue[count];
        ASSERT_NE(msg->from, nullptr);
        ASSERT_NE(msg->from->address, nullptr);
        ASSERT_STREQ(msg->from->address, manager_1_address);
        ASSERT_STREQ(msg->from->user_id, PEP_OWN_USERID);

        ASSERT_NE(msg->to, nullptr);
        pEp_identity* dissolve_to = msg->to->ident;
        ASSERT_NE(dissolve_to, nullptr);
        ASSERT_NE(dissolve_to->user_id, nullptr);
        ASSERT_NE(dissolve_to->address, nullptr);

        status = update_identity(session, dissolve_to);
        ASSERT_OK;

        const char* fpr = dissolve_to->fpr;
        const char* name = dissolve_to->username;
        const char* d_addr = dissolve_to->address;
        const char* d_id = dissolve_to->user_id;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);
        ASSERT_NE(d_addr, nullptr);
        ASSERT_NE(d_id, nullptr);

        int index = -1;

        if (strcmp(d_id, "MEMBER1") == 0)
            index = 0;
        else if (strcmp(d_id, "MEMBER2") == 0)
            index = 1;
        else if (strcmp(d_id, "MEMBER4") == 0)
            index = 2;
        else
            ASSERT_STREQ("This message is just to make the test fail and give a message - unexpected user id in group_dissolve sent mails", d_id);

        ASSERT_STREQ(name, member_names[index]);
        ASSERT_STREQ(d_addr, member_addrs[index]);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;

#if GECT_WRITEOUT
        char* outdata = NULL;
        mime_encode_message(msg, false, &outdata, false);
        ASSERT_NE(outdata, nullptr);
        dump_out((string("test_mails/group_dissolve_") + member_prefixes[index] + ".eml").c_str(), outdata);
        free(outdata);
#endif
    }
    ASSERT_EQ(count, 3);
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(found[i]);
    }

    // Ok, group has all the members. Now we can dissolve the group.
    m_queue.clear(); // Just in case

    free_group(group);
}

TEST_F(GroupEncryptionTest, check_protocol_group_dissolve_receive) {
    // Set up the receive and join actions
    const char* own_id = "PEP_OWN_USERID"; // on purpose, little joke here
    pEp_identity* me = new_identity(member_2_address, NULL, own_id, member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_2_fpr);
    ASSERT_OK;

    // Receive the group creation message
    status = myself(session, me);
    ASSERT_STREQ(me->fpr, member_2_fpr);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    string msg_str = slurp(string("test_mails/group_create_extant_key_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;
    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;


    // Join the group
    pEp_identity* group_identity = new_identity(group_1_address, NULL, own_id, NULL);
    status = myself(session, group_identity);

    bool active = false;
    status = is_group_active(session, group_identity, &active);
    ASSERT_OK;
    ASSERT_TRUE(active);

    pEp_group* group = new_group(group_identity, NULL, NULL);
    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    status = join_group(session, group_identity, me);
    ASSERT_OK;

    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    ASSERT_TRUE(group->members->member->adopted);

    ASSERT_EQ(m_queue.size(), 1);
    m_queue.clear();

    // Now we "receive" a dissolution message from the manager. Make sure it works.
    msg_str = slurp(string("test_mails/group_dissolve_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());
    free_message(msg);
    msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    free_message(dec_msg);
    dec_msg = NULL;
    keylist = NULL;
    flags = 0;
    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    status = retrieve_own_membership_info_for_group_and_identity(session, group, me);
    ASSERT_OK;
    ASSERT_FALSE(group->members->member->adopted);

    active = false;
    status = is_group_active(session, group_identity, &active);
    ASSERT_OK;
    ASSERT_FALSE(active);
}

TEST_F(GroupEncryptionTest, check_protocol_group_join_member_unknown) {
    pEp_identity* me = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* group_ident = new_identity(group_1_address, group_1_fpr, PEP_OWN_USERID, group_1_name);
    read_file_and_import_key(session, kf_name(group_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_1_prefix, true).c_str());
    status = set_own_key(session, group_ident, group_1_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    member_list* new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(new_members, nullptr);
    memberlist_add(new_members, new_member(member_2));

    pEp_group* group = NULL;
    status = group_create(session, group_ident, me, new_members, &group);
    ASSERT_OK;

    ASSERT_EQ(m_queue.size(), 2);
    // Ok, so we've actually already got the messages for this written out elsewhere - this was all DB setup.
    // Let's move on to importing the acceptances - we'll decide only three are going to accept - and then
    // dissolving the group.
    m_queue.clear();

    // Ok, let's get an accept from someone we didn't invite
    string msg_str = slurp(string("test_mails/group_join_") + member_4_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());

    message* msg = NULL;

    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    // Now make sure we didn't do anything with the message
    member_list* group_members = NULL;

    status = retrieve_full_group_membership(session, group_ident, &group_members);
    ASSERT_OK;

    ASSERT_NE(group_members, nullptr);
    ASSERT_NE(group_members->next, nullptr);
    ASSERT_EQ(group_members->next->next, nullptr);

    ASSERT_STRNE(group_members->member->ident->address, member_4_address);
    ASSERT_STRNE(group_members->next->member->ident->address, member_4_address);

}

// Think about this... how do non-synced devices and groups interact?
// Answer: according to vb, they don't, can't, will never happen, etc.
// This kinda needs to be in that spec.
TEST_F(GroupEncryptionTest, check_protocol_group_join_own_group) {

}

TEST_F(GroupEncryptionTest, check_protocol_group_dissolve_group_unknown) {
    // Set up the receive and join actions
    const char* own_id = "PEP_OWN_USERID"; // on purpose, little joke here
    pEp_identity* me = new_identity(member_2_address, NULL, own_id, member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_2_fpr);
    ASSERT_OK;

    // Receive the group creation message
    status = myself(session, me);
    ASSERT_STREQ(me->fpr, member_2_fpr);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());

    // Now we "receive" a dissolution message from the manager. Make sure it works.
    string msg_str = slurp(string("test_mails/group_dissolve_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());
    message* msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;
    PEP_rating rating;
    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    pEp_identity* group_identity = new_identity(group_1_address, NULL, own_id, NULL);
    pEp_group* group = NULL;

    status = retrieve_group_info(session, group_identity, &group);
    ASSERT_NE(status, PEP_STATUS_OK);
    bool active = false;

    status = is_group_active(session, group_identity, &active);
    ASSERT_OK;
    ASSERT_FALSE(active);

}

TEST_F(GroupEncryptionTest, check_protocol_group_create_different_own_identity_managers) {
    pEp_identity* me1 = new_identity(manager_1_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_1_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me1, manager_1_fpr);
    ASSERT_OK;

    pEp_identity* group1_ident = new_identity(group_1_address, group_1_fpr, PEP_OWN_USERID, group_1_name);
    read_file_and_import_key(session, kf_name(group_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_1_prefix, true).c_str());
    status = set_own_key(session, group1_ident, group_1_fpr);
    ASSERT_OK;

    pEp_identity* me2 = new_identity(manager_2_address, NULL, PEP_OWN_USERID, manager_2_name);
    read_file_and_import_key(session, kf_name(manager_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_2_prefix, true).c_str());
    status = set_own_key(session, me2, manager_2_fpr);
    ASSERT_OK;

    pEp_identity* group2_ident = new_identity(group_2_address, group_2_fpr, PEP_OWN_USERID, group_2_name);
    read_file_and_import_key(session, kf_name(group_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_2_prefix, true).c_str());
    status = set_own_key(session, group2_ident, group_2_fpr);
    ASSERT_OK;

    pEp_identity* member_1 = new_identity(member_1_address, NULL, "MEMBER1", member_1_name);
    read_file_and_import_key(session, kf_name(member_1_prefix, false).c_str());
    status = update_identity(session, member_1);
    ASSERT_OK;
    status = set_pEp_version(session, member_1, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_1);
    ASSERT_OK;
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    pEp_identity* member_3 = new_identity(member_3_address, NULL, "MEMBER3", member_3_name);
    read_file_and_import_key(session, kf_name(member_3_prefix, false).c_str());
    status = update_identity(session, member_3);
    ASSERT_OK;
    status = set_pEp_version(session, member_3, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_3);
    ASSERT_OK;
    pEp_identity* member_4 = new_identity(member_4_address, NULL, "MEMBER4", member_4_name);
    read_file_and_import_key(session, kf_name(member_4_prefix, false).c_str());
    status = update_identity(session, member_4);
    ASSERT_OK;
    status = set_pEp_version(session, member_4, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_4);
    ASSERT_OK;

    member_list* g1_new_members = new_memberlist(new_member(member_1));
    ASSERT_NE(g1_new_members, nullptr);
    memberlist_add(g1_new_members, new_member(member_2));
    memberlist_add(g1_new_members, new_member(member_3));
    memberlist_add(g1_new_members, new_member(member_4));

    pEp_group* group1 = NULL;
    status = group_create(session, group1_ident, me1, g1_new_members, &group1);
    ASSERT_OK;

    ASSERT_STREQ(group1->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group1->group_identity->fpr, group_1_fpr);

    ASSERT_EQ(m_queue.size(), 4);

    // Ok, now let's see what's inside the box
    pEp_group* group1_info = NULL;
    status = retrieve_group_info(session, group1_ident, &group1_info);
    ASSERT_OK;
    ASSERT_NE(group1_info, nullptr);

    ASSERT_NE(group1_info->group_identity, nullptr);
    ASSERT_STREQ(group1_ident->address, group1_info->group_identity->address);
    ASSERT_STREQ(group1_ident->user_id, group1_info->group_identity->user_id);

    ASSERT_NE(group1_info->manager, nullptr);
    ASSERT_STREQ(group1_info->manager->user_id, me1->user_id);
    ASSERT_STREQ(group1_info->manager->address, me1->address);

    status = myself(session, group1_info->manager);
    ASSERT_OK;
    ASSERT_NE(group1_info->manager->fpr, nullptr);
    ASSERT_STREQ(group1_info->manager->fpr, manager_1_fpr);
    ASSERT_STREQ(group1_info->manager->username, me1->username);
    ASSERT_STREQ(group1_info->manager->username, manager_1_name);

    ASSERT_TRUE(group1_info->active);

    // Ok, time to check the member list. Tricky...
    const char* member_names[] = {member_1_name, member_2_name, member_3_name, member_4_name};
    const char* member_addrs[] = {member_1_address, member_2_address, member_3_address, member_4_address};
    const char* member_fprs[] = {member_1_fpr, member_2_fpr, member_3_fpr, member_4_fpr};

    bool found[] = {false, false, false};

    int count = 0;
    for (member_list* curr_member = group1_info->members;
            curr_member && curr_member->member && curr_member->member->ident;
            curr_member = curr_member->next) {

        pEp_member* memb = curr_member->member;
        pEp_identity* ident = memb->ident;
        const char* userid = ident->user_id;
        const char* address = ident->address;
        ASSERT_NE(userid, nullptr);
        ASSERT_NE(address, nullptr);

        status = update_identity(session, ident);
        ASSERT_OK;

        const char* fpr = ident->fpr;
        const char* name = ident->username;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);

        ASSERT_FALSE(memb->adopted);

        int index = -1;

        for (int i = 0; i < 4; i++) {
            if (strcmp(member_names[i], name) == 0) {
                index = i;
                break;
            }
        }
        ASSERT_GT(index, -1);
        ASSERT_LT(index, 5);
        ASSERT_STREQ(member_addrs[index], address);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;
        count++;
    }

    ASSERT_EQ(count, 4);
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(found[i]);
    }

    ASSERT_EQ(m_queue.size(), 4);
    for (int i = 0; i < 4; i++) {
        message* msg = m_queue[i];
        ASSERT_NE(msg, nullptr);
        ASSERT_NE(msg->from, nullptr);
        ASSERT_NE(msg->to, nullptr);
        ASSERT_NE(msg->to->ident, nullptr);
        ASSERT_EQ(msg->to->next, nullptr);
        ASSERT_STREQ(msg->from->address, manager_1_address);

#if GECT_WRITEOUT
            char* outdata = NULL;
            mime_encode_message(msg, false, &outdata, false);
            ASSERT_NE(outdata, nullptr);
            dump_out((string("test_mails/group_create_different_own_identity_managers_group_1_") + get_prefix_from_address(msg->to->ident->address) + ".eml").c_str(), outdata);
            free(outdata);
#endif
    }

    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    ASSERT_EQ(m_queue.size(), 0);
    member_list* g2_new_members = new_memberlist(new_member(member_2));
    ASSERT_NE(g2_new_members, nullptr);
    memberlist_add(g2_new_members, new_member(member_3));
    memberlist_add(g2_new_members, new_member(member_4));

    pEp_group* group2 = NULL;
    status = group_create(session, group2_ident, me2, g2_new_members, &group2);
    ASSERT_OK;

    ASSERT_STREQ(group2->manager->fpr, manager_2_fpr);
    ASSERT_STREQ(group2->group_identity->fpr, group_2_fpr);

    // Ok, we now have a bunch of messages to check.
    ASSERT_EQ(m_queue.size(), 3);

    for (int i = 0; i < 3; i++) {
        message* msg = m_queue[i];
        ASSERT_NE(msg, nullptr);
        ASSERT_NE(msg->from, nullptr);
        ASSERT_NE(msg->to, nullptr);
        ASSERT_NE(msg->to->ident, nullptr);
        ASSERT_EQ(msg->to->next, nullptr);
        ASSERT_STREQ(msg->from->address, manager_2_address);

#if GECT_WRITEOUT
            char* outdata = NULL;
            mime_encode_message(msg, false, &outdata, false);
            ASSERT_NE(outdata, nullptr);
            dump_out((string("test_mails/group_create_different_own_identity_managers_group_2_") + get_prefix_from_address(msg->to->ident->address) + ".eml").c_str(), outdata);
            free(outdata);
#endif
    }

    // MESSAGE LIST NOW INVALID.
    m_queue.clear();

    // Ok, now let's see what's inside the box
    pEp_group* group2_info = NULL;
    status = retrieve_group_info(session, group2_ident, &group2_info);
    ASSERT_OK;
    ASSERT_NE(group2_info, nullptr);

    ASSERT_NE(group2_info->group_identity, nullptr);
    ASSERT_STREQ(group2_ident->address, group2_info->group_identity->address);
    ASSERT_STREQ(group2_ident->user_id, group2_info->group_identity->user_id);

    ASSERT_NE(group2_info->manager, nullptr);
    ASSERT_STREQ(group2_info->manager->user_id, me2->user_id);
    ASSERT_STREQ(group2_info->manager->address, me2->address);

    status = myself(session, group2_info->manager);
    ASSERT_OK;
    ASSERT_NE(group2_info->manager->fpr, nullptr);
    ASSERT_STREQ(group2_info->manager->fpr, manager_2_fpr);
    ASSERT_STREQ(group2_info->manager->username, me2->username);
    ASSERT_STREQ(group2_info->manager->username, manager_2_name);

    ASSERT_TRUE(group2_info->active);

    for (int i = 0; i < 4; i++)
        found[i] = false;

    count = 0;
    for (member_list* curr_member = group2_info->members;
            curr_member && curr_member->member && curr_member->member->ident;
            curr_member = curr_member->next) {

        pEp_member* memb = curr_member->member;
        pEp_identity* ident = memb->ident;
        const char* userid = ident->user_id;
        const char* address = ident->address;
        ASSERT_NE(userid, nullptr);
        ASSERT_NE(address, nullptr);

        status = update_identity(session, ident);
        ASSERT_OK;

        const char* fpr = ident->fpr;
        const char* name = ident->username;
        ASSERT_NE(name, nullptr);
        ASSERT_NE(fpr, nullptr);

        ASSERT_FALSE(memb->adopted);

        int index = -1;

        for (int i = 0; i < 4; i++) {
            if (strcmp(member_names[i], name) == 0) {
                index = i;
                break;
            }
        }
        ASSERT_GT(index, -1);
        ASSERT_LT(index, 5);
        ASSERT_STREQ(member_addrs[index], address);
        ASSERT_STREQ(member_fprs[index], fpr);
        found[index] = true;
        count++;
    }

    ASSERT_EQ(count, 3);
    ASSERT_FALSE(found[0]);
    for (int i = 1; i < 4; i++) {
        ASSERT_TRUE(found[i]);
    }

    free_group(group1_info);
    free_group(group2_info);
}

#if GECT_WRITEOUT
// The idea is the next test will import the create from the previous manager and the dissolve from this one.
TEST_F(GroupEncryptionTest, not_a_test_message_gen_for_group_dissolve_not_manager) {
    pEp_identity* me2 = new_identity(manager_2_address, NULL, PEP_OWN_USERID, manager_1_name);
    read_file_and_import_key(session, kf_name(manager_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(manager_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me2, manager_2_fpr);
    ASSERT_OK;

    pEp_identity* group1_ident = new_identity(group_1_address, group_1_fpr, PEP_OWN_USERID, group_1_name);
    read_file_and_import_key(session, kf_name(group_1_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(group_1_prefix, true).c_str());
    status = set_own_key(session, group1_ident, group_1_fpr);
    ASSERT_OK;
    
    pEp_identity* member_2 = new_identity(member_2_address, NULL, "MEMBER2", member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    status = update_identity(session, member_2);
    ASSERT_OK;
    status = set_pEp_version(session, member_2, 2, 2);
    ASSERT_OK;
    status = set_as_pEp_user(session, member_2);
    ASSERT_OK;
    
    member_list* g1_new_members = new_memberlist(new_member(member_2));
    ASSERT_NE(g1_new_members, nullptr);

    pEp_group* group1 = NULL;
    status = group_create(session, group1_ident, me2, g1_new_members, &group1);
    ASSERT_OK;

    ASSERT_STREQ(group1->manager->fpr, manager_2_fpr);
    ASSERT_STREQ(group1->group_identity->fpr, group_1_fpr);

    // We'll get set member2 as joined
    status = set_membership_status(session, group1_ident, member_2, true);
    ASSERT_OK;

    m_queue.clear();
    status = group_dissolve(session, group1_ident, me2);
    ASSERT_EQ(m_queue.size(), 1);

    message* msg = m_queue[0];
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg->from, nullptr);
    ASSERT_NE(msg->to, nullptr);
    ASSERT_NE(msg->to->ident, nullptr);
    ASSERT_EQ(msg->to->next, nullptr);
    ASSERT_STREQ(msg->from->address, manager_2_address);

    char* outdata = NULL;
    mime_encode_message(msg, false, &outdata, false);
    ASSERT_NE(outdata, nullptr);
    dump_out((string("test_mails/group_dissolve_not_manager_") + get_prefix_from_address(msg->to->ident->address) + ".eml").c_str(), outdata);
    free(outdata);

    free_message(msg);

}
#endif

TEST_F(GroupEncryptionTest, check_protocol_group_dissolve_not_manager) {
    // Set up the receive and join actions
    const char* own_id = PEP_OWN_USERID;
    pEp_identity* me = new_identity(member_2_address, NULL, own_id, member_2_name);
    read_file_and_import_key(session, kf_name(member_2_prefix, false).c_str());
    read_file_and_import_key(session, kf_name(member_2_prefix, true).c_str());
    PEP_STATUS status = set_own_key(session, me, member_2_fpr);
    ASSERT_OK;

    string msg_str = slurp(string("test_mails/group_create_different_own_identity_managers_group_1_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());
    message* msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    ASSERT_OK;

    free_message(msg);
    free_message(dec_msg);

    msg_str = slurp(string("test_mails/group_create_different_own_identity_managers_group_2_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());
    msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    dec_msg = NULL;
    keylist = NULL;
    flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    free_message(msg);
    ASSERT_OK;
    free_message(dec_msg);

    pEp_identity* group1_ident = new_identity(group_1_address, NULL, PEP_OWN_USERID, NULL);
    pEp_identity* group2_ident = new_identity(group_2_address, NULL, PEP_OWN_USERID, NULL);

    status = join_group(session, group1_ident, me);
    ASSERT_OK;
    status = join_group(session, group2_ident, me);
    ASSERT_OK;

    m_queue.clear();

    // Now to receive a group dissolve for a group from someone who is not the manager.
    msg_str = slurp(string("test_mails/group_dissolve_not_manager_") + member_2_prefix + ".eml");
    ASSERT_FALSE(msg_str.empty());
    msg = NULL;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    ASSERT_NE(msg, nullptr);

    dec_msg = NULL;
    keylist = NULL;
    flags = 0;

    status = decrypt_message(session, msg, &dec_msg, &keylist, &rating, &flags);
    free_message(msg);
    free_message(dec_msg);
    ASSERT_OK;

    bool active = false;
    status = is_group_active(session, group1_ident, &active);
    ASSERT_OK;
    ASSERT_TRUE(active);

    active = false;
    status = is_group_active(session, group2_ident, &active);
    ASSERT_OK;
    ASSERT_TRUE(active);
}

TEST_F(GroupEncryptionTest, check_protocol_group_dissolve_own_group_receive) {

}

