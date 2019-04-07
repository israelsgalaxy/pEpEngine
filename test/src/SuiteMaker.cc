// This file is under GNU General Public License 3.0
// see LICENSE.txt

//
// src/SuiteMaker.cc generated by gensuitemaker.py - changes may be overwritten. You've been warned!
//

#include <cpptest.h>
#include <cpptest-suite.h>
#include <memory>
#include <vector>
#include "SuiteMaker.h"

// Begin where we generate stuff
#include "MimeTests.h"
#include "OwnIdentitiesRetrieveTests.h"
#include "ExpiredSubkeyTests.h"
#include "DDLUpgradeTests.h"
#include "UserIdCollisionTests.h"
#include "Engine463Tests.h"
#include "BloblistTests.h"
#include "NewUpdateIdAndMyselfTests.h"
#include "NoOwnIdentWritesOnDecryptTests.h"
#include "I18nTests.h"
#include "IdentityListTests.h"
#include "PgpBinaryTests.h"
#include "SubkeyRatingEvalTests.h"
#include "MessageNullFromTests.h"
#include "LeastCommonDenomColorTests.h"
#include "StringlistTests.h"
#include "PgpListKeysTests.h"
#include "MessageApiTests.h"
#include "EncryptMissingPrivateKeyTests.h"
#include "CaseAndDotAddressTests.h"
#include "UserIDAliasTests.h"
#include "EnterLeaveDeviceGroupTests.h"
#include "SignOnlyTests.h"
#include "BCCTests.h"
#include "Engine358Tests.h"
#include "BlacklistAcceptNewKeyTests.h"
#include "DecryptAttachPrivateKeyUntrustedTests.h"
#include "BlacklistTests.h"
#include "RevokeRegenAttachTests.h"
#include "PepSubjectReceivedTests.h"
#include "SequenceTests.h"
#include "HeaderKeyImportTests.h"
#include "EncryptAttachPrivateKeyTests.h"
#include "ExternalRevokeTests.h"
#include "KeyeditTests.h"
#include "LeastColorGroupTests.h"
#include "DecryptAttachPrivateKeyTrustedTests.h"
#include "CheckRenewedExpiredKeyTrustStatusTests.h"
#include "TrustwordsTests.h"
#include "SimpleBodyNotAltTests.h"
#include "ReencryptPlusExtraKeysTests.h"
#include "MapAsn1Tests.h"
#include "DecorateTests.h"
#include "MessageTwoPointOhTests.h"
#include "CrashdumpTests.h"
#include "StringpairListTests.h"
#include "EncryptForIdentityTests.h"
#include "KeyResetMessageTests.h"
#include "KeyAttachmentTests.h"
#include "TrustManipulationTests.h"
#include "SyncTests.h"
#include "AppleMailTests.h"


const char* SuiteMaker::all_suites[] = {
    "MimeTests",
    "OwnIdentitiesRetrieveTests",
    "ExpiredSubkeyTests",
    "DDLUpgradeTests",
    "UserIdCollisionTests",
    "Engine463Tests",
    "BloblistTests",
    "NewUpdateIdAndMyselfTests",
    "NoOwnIdentWritesOnDecryptTests",
    "I18nTests",
    "IdentityListTests",
    "PgpBinaryTests",
    "SubkeyRatingEvalTests",
    "MessageNullFromTests",
    "LeastCommonDenomColorTests",
    "StringlistTests",
    "PgpListKeysTests",
    "MessageApiTests",
    "EncryptMissingPrivateKeyTests",
    "CaseAndDotAddressTests",
    "UserIDAliasTests",
    "EnterLeaveDeviceGroupTests",
    "SignOnlyTests",
    "BCCTests",
    "Engine358Tests",
    "BlacklistAcceptNewKeyTests",
    "DecryptAttachPrivateKeyUntrustedTests",
    "BlacklistTests",
    "RevokeRegenAttachTests",
    "PepSubjectReceivedTests",
    "SequenceTests",
    "HeaderKeyImportTests",
    "EncryptAttachPrivateKeyTests",
    "ExternalRevokeTests",
    "KeyeditTests",
    "LeastColorGroupTests",
    "DecryptAttachPrivateKeyTrustedTests",
    "CheckRenewedExpiredKeyTrustStatusTests",
    "TrustwordsTests",
    "SimpleBodyNotAltTests",
    "ReencryptPlusExtraKeysTests",
    "MapAsn1Tests",
    "DecorateTests",
    "MessageTwoPointOhTests",
    "CrashdumpTests",
    "StringpairListTests",
    "EncryptForIdentityTests",
    "KeyResetMessageTests",
    "KeyAttachmentTests",
    "TrustManipulationTests",
    "SyncTests",
    "AppleMailTests",
};

// This file is generated, so magic constants are ok.
int SuiteMaker::num_suites = 52;

void SuiteMaker::suitemaker_build(const char* test_class_name, const char* test_home, Test::Suite** test_suite) {
    if (strcmp(test_class_name, "MimeTests") == 0)
        *test_suite = new MimeTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "OwnIdentitiesRetrieveTests") == 0)
        *test_suite = new OwnIdentitiesRetrieveTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "ExpiredSubkeyTests") == 0)
        *test_suite = new ExpiredSubkeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "DDLUpgradeTests") == 0)
        *test_suite = new DDLUpgradeTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "UserIdCollisionTests") == 0)
        *test_suite = new UserIdCollisionTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "Engine463Tests") == 0)
        *test_suite = new Engine463Tests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BloblistTests") == 0)
        *test_suite = new BloblistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "NewUpdateIdAndMyselfTests") == 0)
        *test_suite = new NewUpdateIdAndMyselfTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "NoOwnIdentWritesOnDecryptTests") == 0)
        *test_suite = new NoOwnIdentWritesOnDecryptTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "I18nTests") == 0)
        *test_suite = new I18nTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "IdentityListTests") == 0)
        *test_suite = new IdentityListTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "PgpBinaryTests") == 0)
        *test_suite = new PgpBinaryTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SubkeyRatingEvalTests") == 0)
        *test_suite = new SubkeyRatingEvalTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MessageNullFromTests") == 0)
        *test_suite = new MessageNullFromTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "LeastCommonDenomColorTests") == 0)
        *test_suite = new LeastCommonDenomColorTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "StringlistTests") == 0)
        *test_suite = new StringlistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "PgpListKeysTests") == 0)
        *test_suite = new PgpListKeysTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MessageApiTests") == 0)
        *test_suite = new MessageApiTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EncryptMissingPrivateKeyTests") == 0)
        *test_suite = new EncryptMissingPrivateKeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "CaseAndDotAddressTests") == 0)
        *test_suite = new CaseAndDotAddressTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "UserIDAliasTests") == 0)
        *test_suite = new UserIDAliasTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EnterLeaveDeviceGroupTests") == 0)
        *test_suite = new EnterLeaveDeviceGroupTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SignOnlyTests") == 0)
        *test_suite = new SignOnlyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BCCTests") == 0)
        *test_suite = new BCCTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "Engine358Tests") == 0)
        *test_suite = new Engine358Tests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BlacklistAcceptNewKeyTests") == 0)
        *test_suite = new BlacklistAcceptNewKeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "DecryptAttachPrivateKeyUntrustedTests") == 0)
        *test_suite = new DecryptAttachPrivateKeyUntrustedTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BlacklistTests") == 0)
        *test_suite = new BlacklistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "RevokeRegenAttachTests") == 0)
        *test_suite = new RevokeRegenAttachTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "PepSubjectReceivedTests") == 0)
        *test_suite = new PepSubjectReceivedTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SequenceTests") == 0)
        *test_suite = new SequenceTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "HeaderKeyImportTests") == 0)
        *test_suite = new HeaderKeyImportTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EncryptAttachPrivateKeyTests") == 0)
        *test_suite = new EncryptAttachPrivateKeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "ExternalRevokeTests") == 0)
        *test_suite = new ExternalRevokeTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "KeyeditTests") == 0)
        *test_suite = new KeyeditTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "LeastColorGroupTests") == 0)
        *test_suite = new LeastColorGroupTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "DecryptAttachPrivateKeyTrustedTests") == 0)
        *test_suite = new DecryptAttachPrivateKeyTrustedTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "CheckRenewedExpiredKeyTrustStatusTests") == 0)
        *test_suite = new CheckRenewedExpiredKeyTrustStatusTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "TrustwordsTests") == 0)
        *test_suite = new TrustwordsTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SimpleBodyNotAltTests") == 0)
        *test_suite = new SimpleBodyNotAltTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "ReencryptPlusExtraKeysTests") == 0)
        *test_suite = new ReencryptPlusExtraKeysTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MapAsn1Tests") == 0)
        *test_suite = new MapAsn1Tests(test_class_name, test_home);
    else if (strcmp(test_class_name, "DecorateTests") == 0)
        *test_suite = new DecorateTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MessageTwoPointOhTests") == 0)
        *test_suite = new MessageTwoPointOhTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "CrashdumpTests") == 0)
        *test_suite = new CrashdumpTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "StringpairListTests") == 0)
        *test_suite = new StringpairListTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EncryptForIdentityTests") == 0)
        *test_suite = new EncryptForIdentityTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "KeyResetMessageTests") == 0)
        *test_suite = new KeyResetMessageTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "KeyAttachmentTests") == 0)
        *test_suite = new KeyAttachmentTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "TrustManipulationTests") == 0)
        *test_suite = new TrustManipulationTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SyncTests") == 0)
        *test_suite = new SyncTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "AppleMailTests") == 0)
        *test_suite = new AppleMailTests(test_class_name, test_home);
}

void SuiteMaker::suitemaker_buildlist(const char** test_class_names, int num_to_run, const char* test_home, std::vector<Test::Suite*>& test_suites) {
    for (int i = 0; i < num_to_run; i++) {
        Test::Suite* suite = NULL;
        SuiteMaker::suitemaker_build(test_class_names[i], test_home, &suite);
        if (!suite)
            throw std::runtime_error("Could not create a test suite instance."); // FIXME, better error, cleanup, obviously
        test_suites.push_back(suite);
    }
}
void SuiteMaker::suitemaker_buildall(const char* test_home, std::vector<Test::Suite*>& test_suites) {
    SuiteMaker::suitemaker_buildlist(SuiteMaker::all_suites, SuiteMaker::num_suites, test_home, test_suites);
}

