#include "pEpEngine.h"
#include "pEp_internal.h"

// To ensure that the crypto backend correctly wraps the C data
// structures, we pass in the size of each data structure that is
// wrapped as well as a few offsets.  The crypto backend checks that
// these match its declarations and if not panics.
extern PEP_STATUS pgp_init_(PEP_SESSION session, bool in_first,
                            const char *home_dir,
                            unsigned int session_size,
                            unsigned int session_cookie_offset,
                            unsigned int session_curr_passphrase_offset,
                            unsigned int session_new_key_pass_enable,
                            unsigned int session_generation_passphrase_offset,
                            unsigned int session_cipher_suite_offset,
                            unsigned int pep_status_size,
                            unsigned int pep_comm_type_size,
                            unsigned int pep_enc_format_size,
                            unsigned int pep_identity_flags_size,
                            unsigned int pep_cipher_suite_size,
                            unsigned int string_list_item_size,
                            unsigned int pep_identity_size,
                            unsigned int pep_identity_list_item_size,
                            unsigned int timestamp_size);

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
  return pgp_init_(session, in_first,
                   per_user_directory(),
                   sizeof(pEpSession),
                   offsetof(pEpSession, cryptotech_cookie),
                   offsetof(pEpSession, curr_passphrase),
                   offsetof(pEpSession, new_key_pass_enable),
                   offsetof(pEpSession, generation_passphrase),
                   offsetof(pEpSession, cipher_suite),
                   sizeof(PEP_STATUS),
                   sizeof(PEP_comm_type),
                   sizeof(PEP_enc_format),
                   sizeof(identity_flags_t),
                   sizeof(PEP_CIPHER_SUITE),
                   sizeof(stringlist_t),
                   sizeof(pEp_identity),
                   sizeof(identity_list),
                   sizeof(timestamp));
}
