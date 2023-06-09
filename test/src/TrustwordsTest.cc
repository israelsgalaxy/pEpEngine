// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <iostream>
#include <string>
#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for TrustwordsTest
    class TrustwordsTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            TrustwordsTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~TrustwordsTest() override {
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

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the TrustwordsTest suite.

    };

}  // namespace


TEST_F(TrustwordsTest, check_trustwords) {
#define SET_VERSION(identity)                                           \
    do {                                                                \
        int major, minor;                                               \
        if (outer_iteration_i == 0) {                                   \
            /* Latest version: only use RIPEMD-160. */                  \
            major = PEP_PROTOCOL_VERSION_MAJOR;                         \
            minor = PEP_PROTOCOL_VERSION_MINOR;                         \
        }                                                               \
        else {                                                          \
            /* Fall back to xor trustwords. */                          \
            major = 2;                                                  \
            minor = 1;                                                  \
        }                                                               \
        (identity)->major_ver = major;                                  \
        (identity)->minor_ver = minor;                                  \
        status = set_protocol_version(session, (identity),              \
                                      major, minor);                    \
        ASSERT_EQ(status, PEP_STATUS_OK);                               \
    } while (false)

#if defined(PEP_TRUSTWORDS_XOR_COMPATIBILITY)
    int outer_iteration_no = 2;
#else
    int outer_iteration_no = 1;
#endif

    int outer_iteration_i;
    for (outer_iteration_i = 0;
         outer_iteration_i < outer_iteration_no;
         outer_iteration_i ++) {
        output_stream << "\n*** get_trustwords test ***\n\n";

        PEP_STATUS status = PEP_STATUS_OK;

        pEp_identity* identity1  = new_identity(
            "leon.schumacher@digitalekho.com",
            "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
            "23",
            "Leon Schumacher");
        SET_VERSION(identity1);
        pEp_identity* identity2 = new_identity(
            "krista@darthmama.org",
            "62D4932086185C15917B72D30571AFBCA5493553",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity2);

        pEp_identity* identity2_with_spaces = new_identity(
            "krista@darthmama.org",
            " 62D4932086185C159 17B72D30571A FBCA    5493553   ",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity2_with_spaces);

        string fingerprint1 = identity1->fpr;
        string fingerprint2 = identity2->fpr;
        char* words1 = nullptr;
        char* words2 = nullptr;
        char* full_wordlist = nullptr;
        size_t wsize1 = 0;
        size_t wsize2 = 0;
        size_t wsize_full = 0;

        output_stream << "\nTest 1: fpr1 > fpr2, short" << endl;

        output_stream << "\nfinding German trustwords for " << fingerprint1 << "...\n";
        trustwords(session, fingerprint1.c_str(), "de", &words1, &wsize1, 5);
        ASSERT_NOTNULL(words1);
        output_stream << words1 << "\n";

        free(words1);
        words1 = nullptr;

        output_stream << "\nfinding German trustwords for " << fingerprint2 << "...\n";
        trustwords(session, fingerprint2.c_str(), "de", &words2, &wsize2, 5);
        ASSERT_NOTNULL(words2);
        output_stream << words2 << "\n";

        free(words2);
        words1 = nullptr;

        output_stream << "\nfinding German trustwords for " << identity1->address << " and " << identity2->address << "...\n";
        get_trustwords(session, identity1, identity2, "de", &full_wordlist, &wsize_full, false);
        ASSERT_NOTNULL(full_wordlist);
        output_stream << full_wordlist << "\n";

        free(full_wordlist);
        full_wordlist = nullptr;

        output_stream << "\nfinding English trustwords for " << identity1->address << " and " << identity2->address << "... with spaces\n";
        get_trustwords(session, identity1, identity2_with_spaces, "en", &full_wordlist, &wsize_full, false);
        ASSERT_NOTNULL(full_wordlist);
        output_stream << full_wordlist << "\n";

        free(full_wordlist);
        full_wordlist = nullptr;

        output_stream << "\nTest 2: fpr1 == fpr1, short" << endl;

        output_stream << "\nfinding French trustwords for " << fingerprint2 << "...\n";
        trustwords(session, fingerprint2.c_str(), "fr", &words1, &wsize1, 5);
        ASSERT_NOTNULL(words1);
        output_stream << words1 << "\n";

        output_stream << "\nfinding French trustwords for " << identity2->address << " and " << identity2->address << "...\n";
        status = get_trustwords(session, identity2, identity2, "fr", &full_wordlist, &wsize_full, false);
        ASSERT_STRNE(words1, full_wordlist); // flipped since [A_XOR_A]

        output_stream << "\nfinding English trustwords for " << fingerprint2 << "...\n";
        trustwords(session, fingerprint2.c_str(), "en", &words1, &wsize1, 5);
        ASSERT_NOTNULL(words1);
        output_stream << words1 << "\n";

        output_stream << "\nfinding English trustwords for " << identity2->address << " and " << identity2->address << "... with spaces\n";
        get_trustwords(session, identity2, identity2_with_spaces, "en", &full_wordlist, &wsize_full, false);
        ASSERT_STRNE(words1, full_wordlist); // flipped since [A_XOR_A]
        // ASSERT_EQ(status , PEP_TRUSTWORDS_DUPLICATE_FPR);
        // output_stream << "Discovered duplicate fprs as desired" << endl;

        pEp_free(words1);
        words1 = nullptr;
        pEp_free(full_wordlist);
        full_wordlist = nullptr;

        output_stream << "\nTest 3: fpr1 < fpr2, long" << endl;

        output_stream << "\nfinding English trustwords for " << fingerprint2 << "...\n";
        trustwords(session, fingerprint2.c_str(), "en", &words1, &wsize1, 0);
        ASSERT_NOTNULL(words1);
        output_stream << words1 << "\n";

        output_stream << "\nfinding English trustwords for " << fingerprint1 << "...\n";
        trustwords(session, fingerprint1.c_str(), "en", &words2, &wsize2, 0);
        ASSERT_NOTNULL(words2);
        output_stream << words2 << "\n";

        output_stream << "\nfinding English trustwords for " << identity2->address << " and " << identity1->address << "...\n";
        get_trustwords(session, identity2, identity1, "en", &full_wordlist, &wsize_full, true);
        ASSERT_NOTNULL(full_wordlist);
        output_stream << full_wordlist << "\n";

        output_stream << "\nfinding English trustwords for " << identity2->address << " and " << identity1->address << "... with spaces\n";
        get_trustwords(session, identity2_with_spaces, identity1, "en", &full_wordlist, &wsize_full, true);
        ASSERT_NOTNULL(full_wordlist);
        output_stream << full_wordlist << "\n";

        pEp_free(words1);
        words1 = nullptr;
        pEp_free(words2);
        words2 = nullptr;
        pEp_free(full_wordlist);
        full_wordlist = nullptr;

        output_stream << "\nTest 4: fpr1 < fpr2, leading zeros (fpr1 has more), long" << endl;

        pEp_identity* identity3 = new_identity(
            "nobody@darthmama.org",
            "000F932086185C15917B72D30571AFBCA5493553",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity3);

        pEp_identity* identity4 = new_identity(
            "nobody2@darthmama.org",
            "001F932086185C15917B72D30571AFBCA5493553",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity4);

        pEp_identity* identity5 = new_identity(
            "nobody3@darthmama.org",
            "001F732086185C15917B72D30571AFBCA5493553",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity5);

        string fingerprint3 = identity3->fpr;
        string fingerprint4 = identity4->fpr;
        string fingerprint5 = identity5->fpr;

        output_stream << "\nfinding Catalan trustwords for " << fingerprint3 << "...\n";
        trustwords(session, fingerprint3.c_str(), "ca", &words1, &wsize1, 0);
        ASSERT_NOTNULL(words1);
        output_stream << words1 << "\n";

        output_stream << "\nfinding Catalan trustwords for " << fingerprint4 << "...\n";
        trustwords(session, fingerprint4.c_str(), "ca", &words2, &wsize2, 0);
        ASSERT_NOTNULL(words2);
        output_stream << words2 << "\n";

        output_stream << "\nfinding Catalan trustwords for " << identity3->address << " and " << identity4->address << "...\n";
        get_trustwords(session, identity3, identity4, "ca", &full_wordlist, &wsize_full, true);
        ASSERT_NOTNULL(full_wordlist);
        output_stream << full_wordlist << "\n";

        pEp_free(words1);
        words1 = nullptr;
        pEp_free(words2);
        words2 = nullptr;
        pEp_free(full_wordlist);
        full_wordlist = nullptr;

        output_stream << "\nTest 5: fpr1 > fpr2, leading zeros (same number), interior digit difference, short" << endl;

        output_stream << "\nfinding Turkish trustwords for " << fingerprint4 << "...\n";
        trustwords(session, fingerprint4.c_str(), "tr", &words1, &wsize1, 5);
        ASSERT_NOTNULL(words1);
        output_stream << words1 << "\n";

        output_stream << "\nfinding Turkish trustwords for " << fingerprint5 << "...\n";
        trustwords(session, fingerprint5.c_str(), "tr", &words2, &wsize2, 5);
        ASSERT_NOTNULL(words2);
        output_stream << words2 << "\n";

        output_stream << "\nfinding Turkish trustwords for " << identity4->address << " and " << identity5->address << "...\n";
        get_trustwords(session, identity4, identity5, "tr", &full_wordlist, &wsize_full, false);
        ASSERT_NOTNULL(full_wordlist);
        output_stream << full_wordlist << "\n";

        pEp_free(words1);
        words1 = nullptr;
        pEp_free(words2);
        words2 = nullptr;
        pEp_free(full_wordlist);
        full_wordlist = nullptr;

        output_stream << "\nTest 6: fpr2 is shorter" << endl;

        pEp_identity* identity6 = new_identity(
            "nobody4@darthmama.org",
            "F1F932086185c15917B72D30571AFBCA5493553",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity6);

        output_stream << "\nfinding Turkish trustwords for " << identity5->address << " and " << identity6->address << "...\n";
        PEP_STATUS status6 = get_trustwords(session, identity5, identity6, "tr", &full_wordlist, &wsize_full, false);
        ASSERT_EQ(status6 , PEP_STATUS_OK);
        output_stream << full_wordlist << endl;

        pEp_identity* identity7 = new_identity(
            "nobody5@darthmama.org",
            "F01X932086185C15917B72D30571AFBCA5493553",
            "blargh",
            "Krista Bennett");
        SET_VERSION(identity7);

        output_stream << "\nTest 7: fpr2 has a non-hex character" << endl;

        output_stream << "\nfinding Turkish trustwords for " << identity1->address << " and " << identity7->address << "...\n";
        PEP_STATUS status7 = get_trustwords(session, identity1, identity7, "tr", &full_wordlist, &wsize_full, true);
        ASSERT_EQ(status7 , PEP_ILLEGAL_VALUE);
        output_stream << "Illegal digit value correctly recognised." << "\n";


        free_identity(identity1);
        free_identity(identity2);
        free_identity(identity3);
        free_identity(identity4);
        free_identity(identity5);
        free_identity(identity6);
        free_identity(identity7);
    } /* outer iteration loop */
}

TEST_F(TrustwordsTest, check_trustwords_short_trailing_space) {
    // Horrible kludge: these variables are needed for SET_VERSION, which I
    // am reusing from another test case above.
    int outer_iteration_i = 0;
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity* identity1  = new_identity(
        "leon.schumacher@digitalekho.com",
        "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
        "23",
        "Leon Schumacher");
    SET_VERSION(identity1);

    pEp_identity* identity2 = new_identity(
        "krista@darthmama.org",
        "62D4932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Bennett");    
    SET_VERSION(identity2);
        
    char* wordlist = nullptr;
    size_t wsize_full = 0;

    get_trustwords(session, identity1, identity2, "en", &wordlist, &wsize_full, false);        

    // These will be for RIPEMD-160, since we explicitly set the protocol version above.
    ASSERT_NE(wsize_full, 0);
    ASSERT_NOTNULL(wordlist);
    ASSERT_NE(wordlist[wsize_full - 1], ' ');
    ASSERT_STREQ(wordlist, "CHUMASH KIDDER GASEOUS CLASSIFY POLARITY");
}


TEST_F(TrustwordsTest, check_trustwords_long_trailing_space) {
    // Horrible kludge: these variables are needed for SET_VERSION, which I
    // am reusing from another test case above.
    int outer_iteration_i = 0;
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity* identity1  = new_identity(
        "leon.schumacher@digitalekho.com",
        "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
        "23",
        "Leon Schumacher");
    SET_VERSION(identity1);

    pEp_identity* identity2 = new_identity(
        "krista@darthmama.org",
        "62D4932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Bennett");    
    SET_VERSION(identity2);
        
    char* wordlist = nullptr;
    size_t wsize_full = 0;

    // These will be for RIPEMD-160, since we explicitly set the protocol version above.
    get_trustwords(session, identity1, identity2, "en", &wordlist, &wsize_full, true);        

    ASSERT_NE(wsize_full, 0);
    ASSERT_NOTNULL(wordlist);
    ASSERT_NE(wordlist[wsize_full - 1], ' ');
    ASSERT_STREQ(wordlist, "CHUMASH KIDDER GASEOUS CLASSIFY POLARITY ENDANGER GENEVRA CUSTARD DECELERATOR BRONNIE");
}
