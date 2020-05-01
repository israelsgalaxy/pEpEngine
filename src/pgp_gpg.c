// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"
#include "pEp_internal.h"
#include "pgp_gpg.h"

#include <limits.h>

#include "wrappers.h"

#define _GPGERR(X) ((X) & 0xffffL)

#ifdef NODLSYM
#define DLOAD(X) gpg.X = X
#else
#define DLOAD(X) gpg.X = (X ## _t) (intptr_t) dlsym(gpgme, #X); assert(gpg.X)
#endif

static void *gpgme;
static struct gpg_s gpg;

static bool ensure_config_values(stringlist_t *keys, stringlist_t *values, const char* config_file_path)
{
    int r;
    stringlist_t *_k;
    stringlist_t *_v;
    unsigned int i;
    unsigned int found = 0;
    bool eof_nl = 0;
    char * rest = NULL;
    const char* line_end;

#ifdef WIN32
    line_end = "\r\n";
#else
    line_end = "\n";
#endif    

    FILE *f = Fopen(config_file_path, "r");
    if (f == NULL && errno == ENOMEM)
        return false;

    if (f != NULL) {
        static char buf[MAX_LINELENGTH];
        int length = stringlist_length(keys);
        char * s;

        // make sure we 1) have the same number of keys and values
        // and 2) we don't have more key/value pairs than
        // the size of the bitfield used to hold the indices
        // of key/value pairs matching keys in the config file.
        assert(length <= sizeof(unsigned int) * CHAR_BIT);
        assert(length == stringlist_length(values));
        if (!(length == stringlist_length(values) &&
              length <= sizeof(unsigned int) * CHAR_BIT)) {
            Fclose(f);

            return false;
        }

        while ((s = Fgets(buf, MAX_LINELENGTH, f))) {
            char *token = strtok_r(s, " \t\r\n", &rest);
            for (_k = keys, _v = values, i = 1;
                 _k != NULL;
                 _k = _k->next, _v = _v->next, i <<= 1) {

                if (((found & i) != i) && token &&
                    (strncmp(token, _k->value, strlen(_k->value)) == 0)) {
                    found |= i;
                    break;
                }
            }
            if (feof(f)) {
                eof_nl = 1;
                break;
            }
        }

        if (!s && ferror(f))
            return false;
        f = Freopen(config_file_path, "a", f);
    }
    else {
        f = Fopen(config_file_path, "w");
    }

    assert(f);
    if (f == NULL)
        return false;
    
    if (eof_nl)
        r = Fprintf(f, line_end);

    for (i = 1, _k = keys, _v = values; _k != NULL; _k = _k->next,
            _v = _v->next, i <<= 1) {
        if ((found & i) == 0) {
            r = Fprintf(f, "%s %s%s", _k->value, _v->value, line_end);
            assert(r >= 0);
            if (r < 0)
                return false;
        }
    }

    r = Fclose(f);
    assert(r == 0);
    if (r != 0)
        return false;

    return true;
}

char* _undot_address(const char* address) {
    if (!address)
        return NULL;
    
    int addr_len = strlen(address);
    const char* at = strstr(address, "@");
    
    if (!at)
        at = address + addr_len;
        
    char* retval = calloc(1, addr_len + 1);
    assert(retval);
    if (!retval)
        return NULL;

    const char* addr_curr = address;
    char* retval_curr = retval;
    
    while (addr_curr < at) {
        if (*addr_curr == '.') {
            addr_curr++;
            continue;
        }
        *retval_curr = *addr_curr;
        retval_curr++;
        addr_curr++;
    }
    if (*addr_curr == '@')
        strcat(retval_curr, addr_curr);
    
    return retval;
}

static bool _email_heuristic_match(const char* str1, const char* str2) {
    if (!str1 || !str2)
        return false;
        
    if (strcasecmp(str1, str2) == 0)
        return true;
    
    int len1 = strlen(str1);
    int len2 = strlen(str2);
    
    // otherwise, we work against dotted usernames
    const char* at1 = strstr(str1, "@");
    const char* at2 = strstr(str2, "@");
    
    if (!at1)
        at1 = str1 + len1;
    
    if (!at2)
        at2 = str2 + len2;
        
    // This sucks. And is expensive. Here we go.
    const char* str1_curr = str1;
    const char* str2_curr = str2;
    
    while (str1_curr > at1 && str2_curr > at2) {
        if (*str1_curr == '.') {
            str1_curr++;
            continue;
        }

        if (*str2_curr == '.') {
            str2_curr++;
            continue;
        }
        
        if (tolower(*str1_curr) != tolower(*str2_curr))
            return false;
        
        str1_curr++;
        str2_curr++;
    }
    if (str1_curr == at1 && str2_curr == at2)
        return true;
    
    return false;
}

static PEP_STATUS _version_test(const char *s)
{
    char *_s = strdup(s);
    if (!_s)
        return PEP_OUT_OF_MEMORY;

    int major;
    int minor;
    int revision;

    char *lasts = NULL;
    char *p = strtok_r(_s, ".", &lasts);
    if (!p)
        goto unsupported;
    else
        major = atoi(p);

    p = strtok_r(NULL, ".", &lasts);
    if (!p)
        goto unsupported;
    else
        minor = atoi(p);

    p = strtok_r(NULL, ".", &lasts);
    if (!p)
        goto unsupported;
    else
        revision = atoi(p);

    free(_s);
    _s = NULL;

    if (major > 2)
        return PEP_STATUS_OK;

    if (major == 2 && minor > 1)
        return PEP_STATUS_OK;

    if (major == 2 && minor == 0 && revision == 30)
        return PEP_STATUS_OK;

    if (major == 2 && minor == 1 && revision >= 17)
        return PEP_STATUS_OK;

unsupported:
    free(_s);
    return PEP_INIT_UNSUPPORTED_GPG_VERSION;
}

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    bool bResult;

    if (in_first) {
        stringlist_t *conf_keys   = new_stringlist("keyserver");
        stringlist_t *conf_values = new_stringlist("hkp://keys.gnupg.net");

        stringlist_add(conf_keys, "cert-digest-algo");
        stringlist_add(conf_values, "SHA256");

        stringlist_add(conf_keys, "no-emit-version");
        stringlist_add(conf_values, "");

        stringlist_add(conf_keys, "no-comments");
        stringlist_add(conf_values, "");

        stringlist_add(conf_keys, "personal-cipher-preferences");
        stringlist_add(conf_values, "AES AES256 AES192 CAST5");

        stringlist_add(conf_keys, "personal-digest-preferences");
        stringlist_add(conf_values, "SHA256 SHA512 SHA384 SHA224");

        stringlist_add(conf_keys, "ignore-time-conflict");
        stringlist_add(conf_values, "");

        stringlist_add(conf_keys, "allow-freeform-uid");
        stringlist_add(conf_values, "");

#if defined(WIN32) || defined(NDEBUG)
        bResult = ensure_config_values(conf_keys, conf_values, gpg_conf());
#else
        bResult = ensure_config_values(conf_keys, conf_values, gpg_conf(false));
#endif
        free_stringlist(conf_keys);
        free_stringlist(conf_values);

        assert(bResult);
        if (!bResult) {
            status = PEP_INIT_NO_GPG_HOME;
            goto pEp_error;
        }

        conf_keys = new_stringlist("default-cache-ttl");
        conf_values = new_stringlist("300");

        stringlist_add(conf_keys, "max-cache-ttl");
        stringlist_add(conf_values, "1200");

#if defined(WIN32) || defined(NDEBUG)
        bResult = ensure_config_values(conf_keys, conf_values, gpg_agent_conf());
#else        
        bResult = ensure_config_values(conf_keys, conf_values, gpg_agent_conf(false));
#endif
        free_stringlist(conf_keys);
        free_stringlist(conf_values);

        assert(bResult);
        if (!bResult) {
            status = PEP_INIT_CANNOT_CONFIG_GPG_AGENT;
            goto pEp_error;
        }

#ifndef NODLSYM
        gpgme = dlopen(LIBGPGME, RTLD_LAZY);
        if (gpgme == NULL) {
            status = PEP_INIT_CANNOT_LOAD_GPGME;
            goto pEp_error;
        }
#endif

        memset(&gpg, 0, sizeof(struct gpg_s));

        DLOAD(gpgme_get_engine_info);

        gpgme_engine_info_t info;
        int err = gpg.gpgme_get_engine_info(&info);
        assert(err == GPG_ERR_NO_ERROR);
        if (err != GPG_ERR_NO_ERROR)
            return PEP_OUT_OF_MEMORY;

        assert(info->version);
        if (!info->version)
            return PEP_INIT_CANNOT_DETERMINE_GPG_VERSION;

        status = _version_test(info->version);
        if (status != PEP_STATUS_OK)
            return status;

#ifdef NODLSYM
        gpg.gpgme_check = gpgme_check_version;
#else
        gpg.gpgme_check = (gpgme_check_t) (intptr_t) dlsym(gpgme, "gpgme_check_version");
        assert(gpg.gpgme_check);
#endif

        DLOAD(gpgme_set_locale);
        DLOAD(gpgme_new);
        DLOAD(gpgme_release);
        DLOAD(gpgme_set_protocol);
        DLOAD(gpgme_set_armor);
        DLOAD(gpgme_data_new);
        DLOAD(gpgme_data_new_from_mem);
        DLOAD(gpgme_data_new_from_cbs);
        DLOAD(gpgme_data_release);
        DLOAD(gpgme_data_identify);
        DLOAD(gpgme_data_seek);
        DLOAD(gpgme_data_read);
        DLOAD(gpgme_op_decrypt);
        DLOAD(gpgme_op_verify);
        DLOAD(gpgme_op_decrypt_verify);
        DLOAD(gpgme_op_decrypt_result);
        DLOAD(gpgme_op_encrypt_sign);
        DLOAD(gpgme_op_encrypt);
        DLOAD(gpgme_op_sign);
        DLOAD(gpgme_op_verify_result);
        DLOAD(gpgme_signers_clear);
        DLOAD(gpgme_signers_add);
        DLOAD(gpgme_set_passphrase_cb);
        DLOAD(gpgme_get_key);
        DLOAD(gpgme_strerror);
        
#ifdef GPGME_VERSION_NUMBER
#if (GPGME_VERSION_NUMBER >= 0x010700)
        DLOAD(gpgme_op_createkey);
        DLOAD(gpgme_op_createsubkey);
#endif
#endif

        DLOAD(gpgme_op_genkey);
        DLOAD(gpgme_op_genkey_result);
        DLOAD(gpgme_op_delete);
        DLOAD(gpgme_op_import);
        DLOAD(gpgme_op_import_result);
        DLOAD(gpgme_op_export);
        DLOAD(gpgme_set_keylist_mode);
        DLOAD(gpgme_get_keylist_mode);
        DLOAD(gpgme_op_keylist_start);
        DLOAD(gpgme_op_keylist_next);
        DLOAD(gpgme_op_keylist_end);
        DLOAD(gpgme_op_import_keys);
        DLOAD(gpgme_key_ref);
        DLOAD(gpgme_key_unref);
		DLOAD(gpgme_key_release);
        DLOAD(gpgme_op_edit);
        DLOAD(gpgme_io_write);

        gpg.version = gpg.gpgme_check(NULL);

        const char * const cLocal = setlocale(LC_ALL, NULL);
        if (!cLocal || (strcmp(cLocal, "C") == 0))
            setlocale(LC_ALL, "");

        gpg.gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
#ifdef LC_MESSAGES // Windoze
        gpg.gpgme_set_locale (NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif
    }

    gpg.gpgme_check(NULL);
    gpgme_error = gpg.gpgme_new(&session->ctx);
    gpgme_error = _GPGERR(gpgme_error);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        status = PEP_INIT_GPGME_INIT_FAILED;
        goto pEp_error;
    }
    assert(session->ctx);

    gpgme_error = gpg.gpgme_set_protocol(session->ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    gpg.gpgme_set_armor(session->ctx, 1);

    return PEP_STATUS_OK;

pEp_error:
    pgp_release(session, in_first);
    return status;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    if (session->ctx) {
        gpg.gpgme_release(session->ctx);
        session->ctx = NULL;
    }

    if (out_last)
        if (gpgme)
            dlclose(gpgme);
}

PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr
    )
{
    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t cipher, plain;
    gpgme_data_type_t dt;
    gpgme_decrypt_result_t gpgme_decrypt_result = NULL;

    stringlist_t *_keylist = NULL;
    //int i_key = 0;

    assert(session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

    *ptext = NULL;
    *psize = 0;
    *keylist = NULL;

    gpgme_error = gpg.gpgme_data_new_from_mem(&cipher, ctext, csize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new(&plain);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(cipher);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }


    dt = gpg.gpgme_data_identify(cipher);
    switch (dt) {
#if GPGME_VERSION_NUMBER > 0x010600
    case GPGME_DATA_TYPE_PGP_ENCRYPTED:
#endif
    case GPGME_DATA_TYPE_PGP_SIGNED:
    case GPGME_DATA_TYPE_PGP_OTHER:
        if (dsigtext) {
            gpgme_error = gpg.gpgme_op_decrypt(session->ctx, cipher, plain);
        }
        else {
            gpgme_error = gpg.gpgme_op_decrypt_verify(session->ctx, cipher,
                plain);
        }
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
//        assert(gpgme_error != GPG_ERR_NO_DATA);

        switch (gpgme_error) {
            case GPG_ERR_NO_ERROR:
            {
                // EFail: We should get an MDC warning if there were modifications
                //        and never make it here. So the decrypted text is not
                //        returned regardless.
                gpgme_decrypt_result = gpg.gpgme_op_decrypt_result(session->ctx);
                /* NOW is when we have to process the decrypt_result, period.
                   it is only valid until the next call on the context. */
                   
                gpgme_key_t key;
                memset(&key,0,sizeof(key));
                stringlist_t* recipient_keylist = new_stringlist(NULL);
                if (!recipient_keylist) {
                    gpg.gpgme_data_release(plain);
                    gpg.gpgme_data_release(cipher);
                    return PEP_OUT_OF_MEMORY;
                }
               
                if (gpgme_decrypt_result != NULL) {
                    stringlist_t* _keylist = recipient_keylist;
                    for (gpgme_recipient_t r = gpgme_decrypt_result->recipients; r != NULL; r = r->next) {
                        // GPGME may give subkey's fpr instead of primary key's fpr.
                        // Therefore we ask for the primary fingerprint instead
                        // we assume that gpgme_get_key can find key by subkey's fpr
                        gpgme_error = gpg.gpgme_get_key(session->ctx,
                            r->keyid, &key, 0);
                        gpgme_error = _GPGERR(gpgme_error);
                        assert(gpgme_error != GPG_ERR_ENOMEM);
                        if (gpgme_error == GPG_ERR_ENOMEM) {
                            free_stringlist(_keylist);
                            result = PEP_OUT_OF_MEMORY;
                        }
                        // Primary key is given as the first subkey
                        if (gpgme_error == GPG_ERR_NO_ERROR &&
                            key && key->subkeys && key->subkeys->fpr
                            && key->subkeys->fpr[0]) {
                            _keylist = stringlist_add(_keylist, key->subkeys->fpr);
 
                            gpg.gpgme_key_unref(key);
 
                        }
                    }
                    assert(_keylist);
                    if (_keylist == NULL) {
                        free_stringlist(recipient_keylist);
                        if (*keylist)
                            free_stringlist(*keylist);
                        *keylist = NULL;
                        result = PEP_OUT_OF_MEMORY;
                    }
                    // Get filename, if desired
                    if (filename_ptr) {
                        const char* fname = gpgme_decrypt_result->file_name;
                        if (fname) {
                            *filename_ptr = strdup(fname);
                            if (!(*filename_ptr))
                                result = PEP_OUT_OF_MEMORY;
                        }
                    }                    
                } /* Ok, so now we have any recipients it was encrypted for
                     in recipient_keylist */
            
                   
                gpgme_verify_result_t gpgme_verify_result;
                char *_buffer = NULL;
                size_t reading;
                size_t length = gpg.gpgme_data_seek(plain, 0, SEEK_END);
                gpgme_signature_t gpgme_signature;

                assert(length != -1);
                gpg.gpgme_data_seek(plain, 0, SEEK_SET);

                // TODO: make things less memory consuming
                // the following algorithm allocates memory for the complete
                // text

                _buffer = malloc(length + 1);
                assert(_buffer);
                if (_buffer == NULL) {
                    gpg.gpgme_data_release(plain);
                    gpg.gpgme_data_release(cipher);
                    if (recipient_keylist)
                        free_stringlist(recipient_keylist);
                    return PEP_OUT_OF_MEMORY;
                }

                reading = gpg.gpgme_data_read(plain, _buffer, length);
                assert(length == reading);

                if (dsigtext) {  // Is this safe to do?
                    gpgme_data_t sigdata;
                    gpg.gpgme_data_new_from_mem(&sigdata, dsigtext,
                                                dsigsize, 0);
                    gpg.gpgme_op_verify(session->ctx, sigdata, plain, NULL);
                    gpg.gpgme_data_release(sigdata);
                }

                gpgme_verify_result =
                    gpg.gpgme_op_verify_result(session->ctx);
                assert(gpgme_verify_result);
                gpgme_signature = gpgme_verify_result->signatures;

                if (!gpgme_signature) {
                    // try cleartext sig verification
                    gpg.gpgme_op_verify(session->ctx, plain, NULL, plain);
                    gpgme_verify_result =
                        gpg.gpgme_op_verify_result(session->ctx);
                            assert(gpgme_verify_result);
                    gpgme_signature = gpgme_verify_result->signatures;
                }

                if (gpgme_signature) {
                    stringlist_t *k;
                    _keylist = new_stringlist(NULL);
                    assert(_keylist);
                    if (_keylist == NULL) {
                        gpg.gpgme_data_release(plain);
                        gpg.gpgme_data_release(cipher);
                        free(_buffer);
                        return PEP_OUT_OF_MEMORY;
                    }
                    k = _keylist;

                    result = PEP_DECRYPTED_AND_VERIFIED;
                    gpg.gpgme_check(NULL);
                    do { /* get all signers and put them at the front off
                            the keylist (likely only one) */
                        switch (_GPGERR(gpgme_signature->status)) {
                        case GPG_ERR_NO_ERROR:
                        {
                            // Some versions of gpg returns signer's
                            // signing subkey fingerprint instead of
                            // signer's primary key fingerprint.
                            // This is meant to get signer's primary
                            // key fingerprint, using subkey's.

                            gpgme_key_t key = NULL;

                            gpgme_error = gpg.gpgme_get_key(session->ctx,
                                gpgme_signature->fpr, &key, 0);
                            gpgme_error = _GPGERR(gpgme_error);
                            assert(gpgme_error != GPG_ERR_ENOMEM);
                            if (gpgme_error == GPG_ERR_ENOMEM) {
                                free_stringlist(_keylist);
                                gpg.gpgme_data_release(plain);
                                gpg.gpgme_data_release(cipher);
                                free(_buffer);
                                return PEP_OUT_OF_MEMORY;
                            }
                            // Primary key is given as the first subkey
                            if (gpgme_error == GPG_ERR_NO_ERROR &&
                                key && key->subkeys && key->subkeys->fpr
                                && key->subkeys->fpr[0])
                            {
                                k = stringlist_add(k, key->subkeys->fpr);

                                gpg.gpgme_key_unref(key);

                                if (k == NULL) {
                                    free_stringlist(_keylist);
                                    if (recipient_keylist)
                                        free (recipient_keylist);
                                    gpg.gpgme_data_release(plain);
                                    gpg.gpgme_data_release(cipher);
                                    free(_buffer);
                                    return PEP_OUT_OF_MEMORY;
                                }
                            }
                            else
                            {
                                result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                                break;
                            }
                            break;
                        }
                        case GPG_ERR_CERT_REVOKED:
                            result = PEP_VERIFY_SIGNER_KEY_REVOKED;
                            break;
                        case GPG_ERR_BAD_SIGNATURE:
                            result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                            //result = PEP_DECRYPT_BAD_SIGNATURE;
                            break;
                        case GPG_ERR_SIG_EXPIRED:
                        case GPG_ERR_KEY_EXPIRED:
                        case GPG_ERR_NO_PUBKEY:
                            k = stringlist_add(k, gpgme_signature->fpr);
                            if (k == NULL) {
                                free_stringlist(_keylist);
                                if (recipient_keylist)
                                    free_stringlist(recipient_keylist);
                                gpg.gpgme_data_release(plain);
                                gpg.gpgme_data_release(cipher);
                                free(_buffer);
                                return PEP_OUT_OF_MEMORY;
                            }
                            if (result == PEP_DECRYPTED_AND_VERIFIED)
                                result = PEP_DECRYPTED;
                            break;
                        case GPG_ERR_GENERAL:
                            break;
                        default:
                            if (result == PEP_DECRYPTED_AND_VERIFIED)
                                result = PEP_DECRYPTED;
                            break;
                        }
                    } while ((gpgme_signature = gpgme_signature->next));
                }
                else {
                    result = PEP_DECRYPTED;
                }

                if (result == PEP_DECRYPTED_AND_VERIFIED
                    || result == PEP_DECRYPTED) {
                    *ptext = _buffer;
                    *psize = reading;
                    (*ptext)[*psize] = 0; // safeguard for naive users
                    *keylist = _keylist;
                    if (recipient_keylist) {
                        if (!_keylist)
                            *keylist = new_stringlist(""); // no sig
                        if (!(*keylist)) {
                            free_stringlist(_keylist);
                            if (recipient_keylist)
                                free_stringlist(recipient_keylist);
                            gpg.gpgme_data_release(plain);
                            gpg.gpgme_data_release(cipher);
                            free(_buffer);
                            return PEP_OUT_OF_MEMORY;
                        }
                        stringlist_append(*keylist, recipient_keylist);
                    }
                }
                else {
                    free_stringlist(_keylist);
                    if (recipient_keylist)
                        free_stringlist(recipient_keylist);
                    free(_buffer);
                }
                break;
            }
            case GPG_ERR_BAD_PASSPHRASE:
            case GPG_ERR_NO_DATA:
                result = PEP_DECRYPT_NO_KEY;
                break;
            case GPG_ERR_DECRYPT_FAILED:
            default:
            {
                gpgme_decrypt_result = gpg.gpgme_op_decrypt_result(session->ctx);
                result = PEP_DECRYPT_NO_KEY;

                if (gpgme_decrypt_result != NULL) {
                    if (gpgme_decrypt_result->unsupported_algorithm)
                        *keylist = new_stringlist(gpgme_decrypt_result->unsupported_algorithm);
                    else
                        *keylist = new_stringlist("");
                    assert(*keylist);
                    if (*keylist == NULL) {
                        result = PEP_OUT_OF_MEMORY;
                        break;
                    }
                }
            }
        }
        break;

    default:
        result = PEP_DECRYPT_WRONG_FORMAT;
    }

    gpg.gpgme_data_release(plain);
    gpg.gpgme_data_release(cipher);
    return result;
}

PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t d_text, d_sig;
    stringlist_t *_keylist;

    assert(session);
    assert(text);
    assert(size);
    assert(signature);
    assert(sig_size);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = gpg.gpgme_data_new_from_mem(&d_text, text, size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new_from_mem(&d_sig, signature, sig_size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(d_text);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_op_verify(session->ctx, d_sig, d_text, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        gpgme_verify_result_t gpgme_verify_result;
        gpgme_signature_t gpgme_signature;

        gpgme_verify_result =
            gpg.gpgme_op_verify_result(session->ctx);
        assert(gpgme_verify_result);
        gpgme_signature = gpgme_verify_result->signatures;

        if (gpgme_signature) {
            stringlist_t *k;
            _keylist = new_stringlist(NULL);
            assert(_keylist);
            if (_keylist == NULL) {
                gpg.gpgme_data_release(d_text);
                gpg.gpgme_data_release(d_sig);
                return PEP_OUT_OF_MEMORY;
            }
            k = _keylist;

            result = PEP_VERIFIED;
            do {
                gpgme_key_t key;
                memset(&key,0,sizeof(key));

                // GPGME may give subkey's fpr instead of primary key's fpr.
                // Therefore we ask for the primary fingerprint instead
                // we assume that gpgme_get_key can find key by subkey's fpr
                gpgme_error = gpg.gpgme_get_key(session->ctx,
                    gpgme_signature->fpr, &key, 0);
                gpgme_error = _GPGERR(gpgme_error);
                assert(gpgme_error != GPG_ERR_ENOMEM);
                if (gpgme_error == GPG_ERR_ENOMEM) {
                    free_stringlist(_keylist);
                    gpg.gpgme_data_release(d_text);
                    gpg.gpgme_data_release(d_sig);
                    return PEP_OUT_OF_MEMORY;
                }
                // Primary key is given as the first subkey
                if (gpgme_error == GPG_ERR_NO_ERROR &&
                    key && key->subkeys && key->subkeys->fpr
                    && key->subkeys->fpr[0])
                {
                    k = stringlist_add(k, key->subkeys->fpr);

                    gpg.gpgme_key_unref(key);

                    if (k == NULL) {
                        free_stringlist(_keylist);
                        gpg.gpgme_data_release(d_text);
                        gpg.gpgme_data_release(d_sig);
                        return PEP_OUT_OF_MEMORY;
                    }
                }
                else {
                    result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                    break;
                }

                if (gpgme_signature->summary & GPGME_SIGSUM_RED) {
                    if (gpgme_signature->summary & GPGME_SIGSUM_KEY_EXPIRED
                        || gpgme_signature->summary & GPGME_SIGSUM_SIG_EXPIRED) {
                        if (result == PEP_VERIFIED
                            || result == PEP_VERIFIED_AND_TRUSTED)
                            result = PEP_UNENCRYPTED;
                    }
                    else {
                        result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                        break;
                    }
                }
                else {
                    if (gpgme_signature->summary & GPGME_SIGSUM_VALID) {
                        if (result == PEP_VERIFIED)
                            result = PEP_VERIFIED_AND_TRUSTED;
                    }
                    if (gpgme_signature->summary & GPGME_SIGSUM_GREEN) {
                        // good
                    }
                    else if (gpgme_signature->summary & GPGME_SIGSUM_KEY_MISSING) {
                        result = PEP_VERIFY_NO_KEY;
                    }
                    else if (gpgme_signature->summary & GPGME_SIGSUM_SYS_ERROR) {
                        if (result == PEP_VERIFIED
                            || result == PEP_VERIFIED_AND_TRUSTED)
                            result = PEP_UNENCRYPTED;
                    }
                    else {
                        // do nothing
                    }
                }
            } while ((gpgme_signature = gpgme_signature->next));
            *keylist = _keylist;
        }
        else {
            result = PEP_UNENCRYPTED;
        }
        break;
    }
        break;
    case GPG_ERR_NO_DATA:
        result = PEP_DECRYPT_WRONG_FORMAT;
        break;
    case GPG_ERR_INV_VALUE:
    default:
        result = PEP_UNKNOWN_ERROR;
        break;
    }

    gpg.gpgme_data_release(d_text);
    gpg.gpgme_data_release(d_sig);

    return result;
}

PEP_STATUS pgp_sign_only(    
    PEP_SESSION session, const char* fpr, const char *ptext,
    size_t psize, char **stext, size_t *ssize
)
{
    assert(session);
    assert(fpr && fpr[0]);
    assert(ptext);
    assert(psize);
    assert(stext);
    assert(ssize);

    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t plain, signed_text;
    gpgme_key_t* signer_key_ptr;

    gpgme_sig_mode_t sign_mode = GPGME_SIG_MODE_DETACH;
       
    *stext = NULL;
    *ssize = 0;

    gpgme_error = gpg.gpgme_data_new_from_mem(&plain, ptext, psize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new(&signed_text);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(plain);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    signer_key_ptr = calloc(1, sizeof(gpgme_key_t));   
    assert(signer_key_ptr);
    if (signer_key_ptr == NULL) {
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(signed_text);
        return PEP_OUT_OF_MEMORY;
    }

    gpg.gpgme_signers_clear(session->ctx);

    // Get signing key
    gpgme_error = gpg.gpgme_get_key(session->ctx, fpr,
                                    signer_key_ptr, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    gpgme_error_t _gpgme_error;
    
    switch (gpgme_error) {
    case GPG_ERR_ENOMEM:
        gpg.gpgme_key_unref(*signer_key_ptr);
        free(signer_key_ptr);
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(signed_text);
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_NO_ERROR:
        _gpgme_error = gpg.gpgme_signers_add(session->ctx, *signer_key_ptr);
        _gpgme_error = _GPGERR(_gpgme_error);
        assert(_gpgme_error == GPG_ERR_NO_ERROR);
        break;
    case GPG_ERR_EOF:
        gpg.gpgme_key_unref(*signer_key_ptr);
        free(signer_key_ptr);
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(signed_text);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_AMBIGUOUS_NAME:
        gpg.gpgme_key_unref(*signer_key_ptr);
        free(signer_key_ptr);
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(signed_text);
        return PEP_KEY_HAS_AMBIG_NAME;
    default: // GPG_ERR_INV_VALUE if CTX or R_KEY is not a valid pointer or
        // FPR is not a fingerprint or key ID
        gpg.gpgme_key_unref(*signer_key_ptr);
        free(signer_key_ptr);
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(signed_text);
        return PEP_GET_KEY_FAILED;
    }
 
    gpgme_error = gpg.gpgme_op_sign(session->ctx, plain, signed_text, sign_mode);

    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        char *_buffer = NULL;
        size_t reading;
        size_t length = gpg.gpgme_data_seek(signed_text, 0, SEEK_END);
        assert(length != -1);
        gpg.gpgme_data_seek(signed_text, 0, SEEK_SET);

        // TODO: make things less memory consuming
        // the following algorithm allocates a buffer for the complete text

        _buffer = malloc(length + 1);
        assert(_buffer);
        if (_buffer == NULL) {
            gpg.gpgme_key_unref(*signer_key_ptr);
            free(signer_key_ptr);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(signed_text);
            return PEP_OUT_OF_MEMORY;
        }

        reading = gpg.gpgme_data_read(signed_text, _buffer, length);
        assert(length == reading);

        *stext = _buffer;
        *ssize = reading;
        (*stext)[*ssize] = 0; // safeguard for naive users
        result = PEP_STATUS_OK;
        break;
    }
    default:
        result = PEP_UNKNOWN_ERROR;
    }

    gpg.gpgme_key_unref(*signer_key_ptr);
    free(signer_key_ptr);
    gpg.gpgme_data_release(plain);
    gpg.gpgme_data_release(signed_text);
    return result;   
}

static PEP_STATUS pgp_encrypt_sign_optional(    
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize, bool sign
)
{
    PEP_STATUS result;
    gpgme_error_t gpgme_error;
    gpgme_data_t plain, cipher;
    gpgme_key_t *rcpt;
    gpgme_encrypt_flags_t flags;
    const stringlist_t *_keylist;
    int i, j;

    assert(session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    *ctext = NULL;
    *csize = 0;

    gpgme_error = gpg.gpgme_data_new_from_mem(&plain, ptext, psize, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_data_new(&cipher);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if (gpgme_error != GPG_ERR_NO_ERROR) {
        gpg.gpgme_data_release(plain);
        if (gpgme_error == GPG_ERR_ENOMEM)
            return PEP_OUT_OF_MEMORY;
        else
            return PEP_UNKNOWN_ERROR;
    }

    rcpt = calloc(stringlist_length(keylist) + 1, sizeof(gpgme_key_t));
    assert(rcpt);
    if (rcpt == NULL) {
        gpg.gpgme_data_release(plain);
        gpg.gpgme_data_release(cipher);
        return PEP_OUT_OF_MEMORY;
    }

    gpg.gpgme_signers_clear(session->ctx);

    for (_keylist = keylist, i = 0; _keylist != NULL; _keylist = _keylist->next, i++) {
        assert(_keylist->value);
        gpgme_error = gpg.gpgme_get_key(session->ctx, _keylist->value,
            &rcpt[i], 0);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_ENOMEM);

        switch (gpgme_error) {
        case GPG_ERR_ENOMEM:
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_OUT_OF_MEMORY;
        case GPG_ERR_NO_ERROR:
            if (i == 0 && sign) {
                gpgme_error_t _gpgme_error = gpg.gpgme_signers_add(session->ctx, rcpt[0]);
                _gpgme_error = _GPGERR(_gpgme_error);
                assert(_gpgme_error == GPG_ERR_NO_ERROR);
            }
            break;
        case GPG_ERR_EOF:
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_KEY_NOT_FOUND;
        case GPG_ERR_AMBIGUOUS_NAME:
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_KEY_HAS_AMBIG_NAME;
        default: // GPG_ERR_INV_VALUE if CTX or R_KEY is not a valid pointer or
            // FPR is not a fingerprint or key ID
            for (j = 0; j<i; j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_GET_KEY_FAILED;
        }
    }

    // TODO: remove that and replace with proper key management
    flags = GPGME_ENCRYPT_ALWAYS_TRUST;
    
    if (sign) {
        gpgme_error = gpg.gpgme_op_encrypt_sign(session->ctx, rcpt, flags,
            plain, cipher);
    }
    else {
        gpgme_error = gpg.gpgme_op_encrypt(session->ctx, rcpt, flags,
            plain, cipher);
    }
    
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    {
        char *_buffer = NULL;
        size_t reading;
        size_t length = gpg.gpgme_data_seek(cipher, 0, SEEK_END);
        assert(length != -1);
        gpg.gpgme_data_seek(cipher, 0, SEEK_SET);

        // TODO: make things less memory consuming
        // the following algorithm allocates a buffer for the complete text

        _buffer = malloc(length + 1);
        assert(_buffer);
        if (_buffer == NULL) {
            for (j = 0; j<stringlist_length(keylist); j++)
                gpg.gpgme_key_unref(rcpt[j]);
            free(rcpt);
            gpg.gpgme_data_release(plain);
            gpg.gpgme_data_release(cipher);
            return PEP_OUT_OF_MEMORY;
        }

        reading = gpg.gpgme_data_read(cipher, _buffer, length);
        assert(length == reading);

        *ctext = _buffer;
        *csize = reading;
        (*ctext)[*csize] = 0; // safeguard for naive users
        result = PEP_STATUS_OK;
        break;
    }
    default:
        result = PEP_UNKNOWN_ERROR;
    }

    for (j = 0; j<stringlist_length(keylist); j++)
        gpg.gpgme_key_unref(rcpt[j]);
    free(rcpt);
    gpg.gpgme_data_release(plain);
    gpg.gpgme_data_release(cipher);
    return result;
}

PEP_STATUS pgp_encrypt_only(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    return pgp_encrypt_sign_optional(session, keylist, ptext,
        psize, ctext, csize, false);
}

PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    return pgp_encrypt_sign_optional(session, keylist, ptext,
        psize, ctext, csize, true);
}


static PEP_STATUS find_single_key(
        PEP_SESSION session,
        const char *fpr,
        gpgme_key_t *key
    )
{
    gpgme_error_t gpgme_error;

    *key = NULL;

//    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, fpr, 0);

    gpgme_error = gpg.gpgme_get_key(session->ctx, fpr, key, 0);

    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        return PEP_GET_KEY_FAILED;
    };

//    gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, key);
//    gpgme_error = _GPGERR(gpgme_error);
//    assert(gpgme_error != GPG_ERR_INV_VALUE);

//    gpg.gpgme_op_keylist_end(session->ctx);

    return PEP_STATUS_OK;
}


static PEP_STATUS _pgp_createkey(PEP_SESSION session, pEp_identity *identity) {
    PEP_STATUS status = PEP_VERSION_MISMATCH;

    if (identity && identity->address) {
#ifdef GPGME_VERSION_NUMBER 
#if (GPGME_VERSION_NUMBER >= 0x010700)
        gpgme_error_t gpgme_error;
        int userid_size = strlen(identity->address) + 1;
        char* userid = (char*)(calloc(1, userid_size));
        if (!userid)
            return PEP_OUT_OF_MEMORY;
        strlcpy(userid, identity->address, userid_size);
        gpgme_error = gpg.gpgme_op_createkey(session->ctx, userid, "RSA", 
                                             0, 31536000, NULL, 
                                             GPGME_CREATE_NOPASSWD | GPGME_CREATE_FORCE);
        gpgme_error = _GPGERR(gpgme_error);

        free(userid);

        if (gpgme_error != GPG_ERR_NOT_SUPPORTED) {
            switch (gpgme_error) {
                case GPG_ERR_NO_ERROR:
                    break;
                case GPG_ERR_INV_VALUE:
                    return PEP_ILLEGAL_VALUE;
                default:
                    return PEP_CANNOT_CREATE_KEY;
            }

            /* This is the same regardless of whether we got it from genkey or createkey */
            gpgme_genkey_result_t gpgme_genkey_result = gpg.gpgme_op_genkey_result(session->ctx);
            assert(gpgme_genkey_result);
            assert(gpgme_genkey_result->fpr);

            char* fpr = strdup(gpgme_genkey_result->fpr);
            gpgme_key_t key;
            PEP_STATUS key_status = find_single_key(session, fpr, &key);
            if (!key || key_status != PEP_STATUS_OK)
                return PEP_CANNOT_CREATE_KEY;
            
            gpgme_error = gpg.gpgme_op_createsubkey(session->ctx, key, 
                                                    "RSA", 0, 
                                                    31536000, GPGME_CREATE_NOPASSWD 
                                                    | GPGME_CREATE_ENCR);

            switch (gpgme_error) {
                case GPG_ERR_NO_ERROR:
                    break;
                case GPG_ERR_INV_VALUE:
                    return PEP_ILLEGAL_VALUE;
                case GPG_ERR_GENERAL:
                    return PEP_CANNOT_CREATE_KEY;
                default:
                    assert(0);
                    return PEP_UNKNOWN_ERROR;
            }
            
            free(identity->fpr);
            identity->fpr = fpr;
            if (identity->fpr == NULL)
                return PEP_OUT_OF_MEMORY;

//            gpg.gpgme_key_unref(key);
            
            status = pgp_replace_only_uid(session, fpr,
                        identity->username, identity->address);
        }
#endif
#endif
    }
    
    return status;
}

PEP_STATUS pgp_generate_keypair(
    PEP_SESSION session, pEp_identity *identity
    )
{
    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL || identity->fpr[0] == 0);
    assert(identity->username);

    PEP_STATUS status = _pgp_createkey(session, identity);
    
    if (status != PEP_VERSION_MISMATCH)
        return status;
        
    gpgme_error_t gpgme_error;
    char *parms;
    const char *template =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 4096\n"
        "Name-Real: %s\n"
        "Name-Email: %s\n"
        /* "Passphrase: %s\n" */
        "Expire-Date: 1y\n"
        "</GnupgKeyParms>\n";
    int result;

    parms = calloc(1, PARMS_MAX);
    assert(parms);
    if (parms == NULL)
        return PEP_OUT_OF_MEMORY;

    result = snprintf(parms, PARMS_MAX, template, identity->username,
        identity->address); // , session->passphrase);
    assert(result < PARMS_MAX);
    if (result >= PARMS_MAX) {
        free(parms);
        return PEP_BUFFER_TOO_SMALL;
    }

    gpgme_error = gpg.gpgme_op_genkey(session->ctx, parms, NULL, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    free(parms);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        return PEP_ILLEGAL_VALUE;
    case GPG_ERR_GENERAL:
        return PEP_CANNOT_CREATE_KEY;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_genkey_result_t gpgme_genkey_result = gpg.gpgme_op_genkey_result(session->ctx);
    assert(gpgme_genkey_result);
    assert(gpgme_genkey_result->fpr);

    free(identity->fpr);
    identity->fpr = strdup(gpgme_genkey_result->fpr);
    if (identity->fpr == NULL)
        return PEP_OUT_OF_MEMORY;

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr)
{
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);

    gpgme_error = gpg.gpgme_get_key(session->ctx, fpr, &key, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        return PEP_ILLEGAL_VALUE;
    case GPG_ERR_AMBIGUOUS_NAME:
        return PEP_KEY_HAS_AMBIG_NAME;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = gpg.gpgme_op_delete(session->ctx, key, 1);
    gpgme_error = _GPGERR(gpgme_error);
    gpg.gpgme_key_unref(key);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_PUBKEY:
        assert(0);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_AMBIGUOUS_NAME:
        assert(0);
        return PEP_KEY_HAS_AMBIG_NAME;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents)
{
    gpgme_error_t gpgme_error;
    gpgme_data_t dh;

    assert(session);
    assert(key_data);

    if(private_idents)
        *private_idents = NULL;

    gpgme_error = gpg.gpgme_data_new_from_mem(&dh, key_data, size, 0);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_import_result_t gpgme_import_result;

    bool key_imported = false;
    
    gpgme_error = gpg.gpgme_op_import(session->ctx, dh);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
    
        gpgme_import_result =
            gpg.gpgme_op_import_result(session->ctx);
        assert(gpgme_import_result);
        if (!gpgme_import_result) {
            gpg.gpgme_data_release(dh);
            return PEP_UNKNOWN_ERROR;
        }
        // considered seems to only be true if it was 
        // actually a key
        if (gpgme_import_result->considered > 0)
            // gpgme_import_result->imported > 0 ||
            // gpgme_import_result->secret_imported > 0 ||
            // gpgme_import_result->unchanged > 0 ||
            // gpgme_import_result->secret_unchanged > 0)
            key_imported = true;
            
        if(private_idents)
        {
            gpgme_import_status_t import;
            for (import = gpgme_import_result->imports;
                 import;
                 import = import->next)
             {
                if (import &&
                    import->result == GPG_ERR_NO_ERROR &&
                    import->status & GPGME_IMPORT_SECRET )
                {
                    gpgme_key_t key = NULL;

                    gpgme_error = gpg.gpgme_get_key(session->ctx,
                        import->fpr, &key, 0);
                    gpgme_error = _GPGERR(gpgme_error);
                    assert(gpgme_error != GPG_ERR_ENOMEM);
                    if (gpgme_error == GPG_ERR_ENOMEM) {
                        gpg.gpgme_data_release(dh);
                        return PEP_OUT_OF_MEMORY;
                    }

                    if (gpgme_error == GPG_ERR_NO_ERROR &&
                        key && key->uids &&
                        key->uids->email && key->uids->name)
                    {
                        pEp_identity *ident = new_identity(
                             key->uids->email, import->fpr, NULL, key->uids->name);

                        gpg.gpgme_key_unref(key);

                        if (ident == NULL) {
                            gpg.gpgme_data_release(dh);
                            return PEP_OUT_OF_MEMORY;
                        }

                        *private_idents = identity_list_add(*private_idents, ident);

                        if (*private_idents == NULL) {
                            gpg.gpgme_data_release(dh);
                            return PEP_OUT_OF_MEMORY;
                        }
                    }
                    else
                    {
                        gpg.gpgme_key_unref(key);
                        gpg.gpgme_data_release(dh);
                        return PEP_UNKNOWN_ERROR;
                    }
                }
            }
        }
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_DATA:
        gpg.gpgme_data_release(dh);
        return PEP_ILLEGAL_VALUE;
    default:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    }

    gpg.gpgme_data_release(dh);
    
    if (key_imported)
        return PEP_KEY_IMPORTED;
        
    return PEP_NO_KEY_IMPORTED;
}

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
    )
{
    gpgme_error_t gpgme_error;
    gpgme_data_t dh;
    size_t _size;
    char *buffer = NULL;
    int reading;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(size);

    gpgme_error = gpg.gpgme_data_new(&dh);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    if (secret)
        gpgme_error = gpg.gpgme_op_export(session->ctx, fpr,
            GPGME_EXPORT_MODE_SECRET, dh);
    else
        gpgme_error = gpg.gpgme_op_export(session->ctx, fpr,
            GPGME_EXPORT_MODE_MINIMAL, dh);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        gpg.gpgme_data_release(dh);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        gpg.gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    };

    _size = gpg.gpgme_data_seek(dh, 0, SEEK_END);
    assert(_size != -1);
    gpg.gpgme_data_seek(dh, 0, SEEK_SET);

    // Unfortunately, gpgme doesn't give us an error
    // when no key is found, so we end up with an 
    // empty string. So we need to do this:
    if (_size == 0) {
        *key_data = NULL;
        *size = 0;
        gpg.gpgme_data_release(dh);
        return PEP_KEY_NOT_FOUND;
    }
        
    buffer = malloc(_size + 1);
    assert(buffer);
    if (buffer == NULL) {
        gpg.gpgme_data_release(dh);
        return PEP_OUT_OF_MEMORY;
    }

    reading = gpg.gpgme_data_read(dh, buffer, _size);
    assert(_size == reading);
    if(_size != reading)
        return PEP_CANNOT_EXPORT_KEY;

    // safeguard for the naive user
    buffer[_size] = 0;

    *key_data = buffer;
    *size = _size;

    gpg.gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_list_keyinfo(PEP_SESSION session, const char* pattern,
                            stringpair_list_t** keyinfo_list)
{
    gpgme_error_t gpgme_error;
    assert(session);
    assert(keyinfo_list);

    if (!session || !keyinfo_list)
        return PEP_ILLEGAL_VALUE;

    *keyinfo_list = NULL;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, pattern, 0);
    gpgme_error = _GPGERR(gpgme_error);

    switch(gpgme_error) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_INV_VALUE:
            assert(0);
            return PEP_UNKNOWN_ERROR;
        default:
            gpg.gpgme_op_keylist_end(session->ctx);
            return PEP_GET_KEY_FAILED;
    };

    gpgme_key_t key;
    stringpair_list_t* _keyinfo_list = new_stringpair_list(NULL);
    stringpair_list_t* list_curr = _keyinfo_list;
    stringpair_t* pair = NULL;

    do {
        gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);

        switch(gpgme_error) {
            case GPG_ERR_EOF:
                break;
            case GPG_ERR_NO_ERROR:
                assert(key);
                assert(key->subkeys);
                if (!key || !key->subkeys)
                    return PEP_GET_KEY_FAILED;

                // first subkey is primary key
                char* fpr = key->subkeys->fpr;
                char* uid = key->uids->uid;

                assert(fpr);
                assert(uid);
                if (!fpr)
                    return PEP_GET_KEY_FAILED;

                if (key->subkeys->revoked)
                    continue;

                pair = new_stringpair(fpr, uid);

                assert(pair);

                if (pair) {
                    list_curr = stringpair_list_add(list_curr, pair);
                    pair = NULL;

                    assert(list_curr);
                    if (list_curr != NULL)
                        break;
                    else
                        free_stringpair(pair);
                }
                // else fallthrough (list_curr or pair wasn't allocateable)
            case GPG_ERR_ENOMEM:
                free_stringpair_list(_keyinfo_list);
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_OUT_OF_MEMORY;
            default:
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_UNKNOWN_ERROR;
        }
    } while (gpgme_error != GPG_ERR_EOF);

    if (_keyinfo_list->value == NULL) {
        free_stringpair_list(_keyinfo_list);
        _keyinfo_list = NULL;
    }

    *keyinfo_list = _keyinfo_list;

    return PEP_STATUS_OK;
}

static void _switch_mode(pEpSession *session, gpgme_keylist_mode_t remove_mode,
    gpgme_keylist_mode_t add_mode)
{
    gpgme_error_t gpgme_error;
    gpgme_keylist_mode_t mode;

    mode = gpg.gpgme_get_keylist_mode(session->ctx);

    mode &= ~remove_mode;
    mode |= add_mode;

    gpgme_error = gpg.gpgme_set_keylist_mode(session->ctx, mode);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
}

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(pattern);

    _switch_mode(session, GPGME_KEYLIST_MODE_LOCAL, GPGME_KEYLIST_MODE_EXTERN);

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, pattern, 0);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
        return PEP_UNKNOWN_ERROR;
    default:
        _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
        return PEP_GET_KEY_FAILED;
    };

    gpgme_ctx_t import_ctx;
    gpgme_error = gpg.gpgme_new(&import_ctx);
    assert(gpgme_error == GPG_ERR_NO_ERROR);

    do {
        gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
        case GPG_ERR_EOF:
            break;
        case GPG_ERR_NO_ERROR:
        {
            gpgme_error_t gpgme_error;
            gpgme_key_t keys[2];

            keys[0] = key;
            keys[1] = NULL;

            gpgme_error = gpg.gpgme_op_import_keys(import_ctx, keys);
            gpgme_error = _GPGERR(gpgme_error);
            gpg.gpgme_key_unref(key);
            assert(gpgme_error != GPG_ERR_INV_VALUE);
            assert(gpgme_error != GPG_ERR_CONFLICT);
        }
            break;
        case GPG_ERR_ENOMEM:
            gpg.gpgme_op_keylist_end(session->ctx);
            gpg.gpgme_release(import_ctx);
            _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
            return PEP_OUT_OF_MEMORY;
        default:
            gpg.gpgme_op_keylist_end(session->ctx);
            gpg.gpgme_release(import_ctx);
            _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
            return PEP_UNKNOWN_ERROR;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    gpg.gpgme_op_keylist_end(session->ctx);
    gpg.gpgme_release(import_ctx);
    _switch_mode(session, GPGME_KEYLIST_MODE_EXTERN, GPGME_KEYLIST_MODE_LOCAL);
    return PEP_STATUS_OK;
}

static PEP_STATUS _pgp_search_keys(PEP_SESSION session, const char* pattern,
                            stringlist_t** keylist,
                            int private_only) {
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, pattern, private_only);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_INV_VALUE:
            assert(0);
            return PEP_UNKNOWN_ERROR;
        default:
            gpg.gpgme_op_keylist_end(session->ctx);
            return PEP_GET_KEY_FAILED;
    };

    stringlist_t *_keylist = new_stringlist(NULL);
    stringlist_t *_k = _keylist;

    do {
        gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
            case GPG_ERR_EOF:
                break;
            case GPG_ERR_NO_ERROR:
                assert(key);
                assert(key->subkeys);
                if(!key->subkeys)
                    break;
                assert(key->uids);
                gpgme_user_id_t kuid = key->uids;
                // check that at least one uid's email matches pattern exactly,
                // modulo the email-diff heuristic
                while(kuid) {
                    if((pattern == NULL) ||
                       (strstr(pattern, "@") == NULL) || // not an email
                       (kuid->email && _email_heuristic_match(kuid->email, pattern)))
                    { 
                        char *fpr = key->subkeys->fpr;
                        assert(fpr);
                        _k = stringlist_add(_k, fpr);
                        assert(_k);
                        if (_k == NULL){
                            free_stringlist(_keylist);
                            gpg.gpgme_op_keylist_end(session->ctx);
                            return PEP_OUT_OF_MEMORY;
                        }
                        break;
                    }
                    kuid = kuid->next;
                }
                break;
            case GPG_ERR_ENOMEM:
                free_stringlist(_keylist);
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_OUT_OF_MEMORY;
            default:
                gpg.gpgme_op_keylist_end(session->ctx);
                return PEP_UNKNOWN_ERROR;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    gpg.gpgme_op_keylist_end(session->ctx);
    if (_keylist->value == NULL) {
        free_stringlist(_keylist);
        _keylist = NULL;
        
        if (pattern != NULL) {
            // If match failed, check to see if we've got a dotted address in the pattern.
            // (last chance of the heuristic, really)
            // If so, try again without any dots.
            const char* dotpos = strstr(pattern, ".");
            const char* atpos = strstr(pattern, "@");
            if (dotpos && atpos && (dotpos < atpos)) {
                char* undotted = _undot_address(pattern);
                if (undotted) {
                    PEP_STATUS status = _pgp_search_keys(session, undotted,
                                                         keylist, private_only);
                    free(undotted);
                    return status;
                }
            }
        }
    }    
    
    *keylist = _keylist;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    return _pgp_search_keys(session, pattern, keylist, 0);
}

PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
)
{
    return _pgp_search_keys(session, pattern, keylist, 1);
}

// this function is delivering a list of triples with fpr, email, name of all
// ultimatedly trusted private keys

PEP_STATUS pgp_find_trusted_private_keys(
        PEP_SESSION session, stringlist_t **keylist
    )
{
    assert(session && keylist);
    if (!session || !keylist)
        return PEP_ILLEGAL_VALUE;

    *keylist = NULL;

    gpgme_key_t key;
    gpgme_error_t gpgme_error;

    stringlist_t *private_keylist = NULL;
    PEP_STATUS status = pgp_find_private_keys(session, NULL, &private_keylist);
    if (status)
        return status;
    if (!private_keylist || !private_keylist->value)
        return status;

    stringlist_t *result_list = new_stringlist(NULL);
    if (!result_list)
        return PEP_OUT_OF_MEMORY;
    stringlist_t *_result_list = result_list;

    stringlist_t *keylist_curr;
    for (keylist_curr = private_keylist; keylist_curr && keylist_curr->value; keylist_curr = keylist_curr->next) {
        // a. get key data
        gpgme_error = gpg.gpgme_get_key(session->ctx, keylist_curr->value, &key, 1);
        gpgme_error = _GPGERR(gpgme_error);
        assert(gpgme_error != GPG_ERR_ENOMEM);
        switch (gpgme_error) {
            case GPG_ERR_NO_ERROR:
                break;
            case GPG_ERR_EOF:
                status = PEP_KEY_NOT_FOUND;
                break;
            case GPG_ERR_INV_VALUE:
                status = PEP_ILLEGAL_VALUE;
                break;
            case GPG_ERR_AMBIGUOUS_NAME:
                status = PEP_KEY_HAS_AMBIG_NAME;
                break;
            case GPG_ERR_ENOMEM:
                free_stringlist(result_list);
                free_stringlist(private_keylist);
                return PEP_OUT_OF_MEMORY;
            default:
                assert(0);
                status = PEP_UNKNOWN_ERROR;
        }
        if (key && gpgme_error == GPG_ERR_NO_ERROR) {
            if (key->revoked || key->disabled) {
                status = PEP_KEY_UNSUITABLE;
            }
            else {
                if (key->fpr && key->secret && key->can_encrypt && key->can_sign) {
                    if (key->owner_trust == GPGME_VALIDITY_ULTIMATE &&
                            key->uids && key->uids->email && key->uids->name) { 
                        _result_list = stringlist_add(_result_list, key->fpr);
                        if (!_result_list) {
                            free_stringlist(result_list);
                            free_stringlist(private_keylist);
                            return PEP_OUT_OF_MEMORY;
                        }
                        _result_list = stringlist_add(_result_list, key->uids->email);
                        if (!_result_list) {
                            free_stringlist(result_list);
                            free_stringlist(private_keylist);
                            return PEP_OUT_OF_MEMORY;
                        }
                        _result_list = stringlist_add(_result_list, key->uids->name);
                        if (!_result_list) {
                            free_stringlist(result_list);
                            free_stringlist(private_keylist);
                            return PEP_OUT_OF_MEMORY;
                        }
                    }
                }
            }
        }
    }

    free_stringlist(private_keylist);
    *keylist = result_list;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    gpgme_error_t gpgme_error;

    assert(session);
    assert(pattern);

    gpgme_error = gpg.gpgme_op_export(session->ctx, pattern,
        GPGME_EXPORT_MODE_EXTERN, NULL);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);
    if (gpgme_error == GPG_ERR_NO_ERROR)
        return PEP_STATUS_OK;
    else
        return PEP_CANNOT_SEND_KEY;
}

PEP_STATUS pgp_get_key_rating(
    PEP_SESSION session,
    const char *fpr,
    PEP_comm_type *comm_type
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    gpgme_error = gpg.gpgme_op_keylist_start(session->ctx, fpr, 0);
    gpgme_error = _GPGERR(gpgme_error);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        return PEP_GET_KEY_FAILED;
    };

    gpgme_error = gpg.gpgme_op_keylist_next(session->ctx, &key);
    gpgme_error = _GPGERR(gpgme_error);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    if (key == NULL) {
        gpg.gpgme_op_keylist_end(session->ctx);
        return PEP_KEY_NOT_FOUND;
    }

    switch (key->protocol) {
    case GPGME_PROTOCOL_OpenPGP:
    case GPGME_PROTOCOL_DEFAULT:
        *comm_type = PEP_ct_OpenPGP_unconfirmed;
        break;
    case GPGME_PROTOCOL_CMS:
        *comm_type = PEP_ct_CMS_unconfirmed;
        break;
    default:
        *comm_type = PEP_ct_unknown;
        gpg.gpgme_op_keylist_end(session->ctx);
        return PEP_STATUS_OK;
    }
    

    // N.B. and FIXME 
    // We could get a key with a bad signing subkey and a good encryption
    // subkey. For now, we reject this, because it forces large changes in
    // how we rate keys. It's on the to-do list, but it's low priority.
    // We don't really want to be doing much for tinkered keys in the first
    // place.
    switch (gpgme_error) {
    case GPG_ERR_EOF:
        break;
    case GPG_ERR_NO_ERROR:
        assert(key);
        assert(key->subkeys);
        
        // is main key expired or revoked? If so, we can cut short this nonsense.
        if (key->invalid)
            *comm_type = PEP_ct_key_b0rken;
        else if (key->revoked)
            *comm_type = PEP_ct_key_revoked;            
        else if (key->expired)
            *comm_type = PEP_ct_key_expired;
        else if (!key->subkeys)
            *comm_type = PEP_ct_key_b0rken;
        else {
            // Ok, so we now need to check subkeys. Normally, we could just
            // shortcut this by looking at key->can_sign and key->can_encrypt,
            // but we want the REASON we can't use a key, so this gets ugly.
            PEP_comm_type max_comm_type = *comm_type;

            // NOTE: 
            // PEP_ct_pEp functions here as an unreachable top;
            // it is impossible on just a key.
            // IF THIS CHANGES, we must choose something else.
            PEP_comm_type worst_sign = PEP_ct_pEp;
            PEP_comm_type worst_enc = PEP_ct_pEp;

            PEP_comm_type error_sign = PEP_ct_unknown;
            PEP_comm_type error_enc = PEP_ct_unknown;

            // We require that the underlying client NOT force-use expired or revoked
            // subkeys instead of a valid one.
            //
            // So here we check all the subkeys; we make note of the existence
            // of an expired, revoked, or invalid subkey, in case there is no
            // other alternative (we want to return useful information).
            // At the same time, we try to evaluate the least strong useable keys 
            // for signing and encryption. If there is a useable one of both,
            // the key comm_type corresponds to the lesser of these two least strong
            // keys
            for (gpgme_subkey_t sk = key->subkeys; sk != NULL; sk = sk->next) {
                
                // Only evaluate signing keys or encryption keys
                if (sk->can_sign || sk->can_encrypt) {
                    PEP_comm_type curr_sign = PEP_ct_no_encryption;
                    PEP_comm_type curr_enc = PEP_ct_no_encryption;

#ifdef GPGME_PK_ECC                    
                    if ((sk->pubkey_algo != GPGME_PK_ECC && sk->length < 1024) 
                        || (sk->pubkey_algo == GPGME_PK_ECC && sk->length < 160)) {
#else
                    if (sk->length < 1024) {                        
#endif                        
                        if (sk->can_sign)
                            curr_sign = PEP_ct_key_too_short;
                        if (sk->can_encrypt)                               
                            curr_enc = PEP_ct_key_too_short;
                    }
                    else if 
                        (
                            (((sk->pubkey_algo == GPGME_PK_RSA)
                                || (sk->pubkey_algo == GPGME_PK_RSA_E)
                                || (sk->pubkey_algo == GPGME_PK_RSA_S))
                                && sk->length == 1024)
#ifdef GPGME_PK_ECC                    
                            || (sk->pubkey_algo == GPGME_PK_ECC
                                && sk->length == 160)
#endif                             
                        ) {
                        if (sk->can_sign)
                            curr_sign = PEP_ct_OpenPGP_weak_unconfirmed;
                        if (sk->can_encrypt)                               
                            curr_enc = PEP_ct_OpenPGP_weak_unconfirmed;
                    }
                    else {
                        if (sk->can_sign)
                            curr_sign = max_comm_type;
                        if (sk->can_encrypt)
                            curr_enc = max_comm_type;
                    }
                    if (sk->invalid) {
                        if (sk->can_sign)
                            curr_sign = PEP_ct_key_b0rken;
                        if (sk->can_encrypt)                               
                            curr_enc = PEP_ct_key_b0rken;
                    }
                    if (sk->expired) {
                        if (sk->can_sign)
                            curr_sign = PEP_ct_key_expired;
                        if (sk->can_encrypt)                               
                            curr_enc = PEP_ct_key_expired;
                    }
                    if (sk->revoked) {
                        if (sk->can_sign)
                            curr_sign = PEP_ct_key_revoked;
                        if (sk->can_encrypt)                               
                            curr_enc = PEP_ct_key_revoked;
                    }
                    switch (curr_sign) {
                        case PEP_ct_key_b0rken:
                        case PEP_ct_key_expired:
                        case PEP_ct_key_revoked:
                            error_sign = curr_sign;
                            break;
                        default:    
                            if (sk->can_sign)
                                worst_sign = _MIN(curr_sign, worst_sign);
                            break;
                    }
                    switch (curr_enc) {
                        case PEP_ct_key_b0rken:
                        case PEP_ct_key_expired:
                        case PEP_ct_key_revoked:
                            error_sign = curr_sign;
                            break;
                        default:    
                            if (sk->can_encrypt)
                                worst_enc = _MIN(curr_enc, worst_enc);
                            break;
                    }                    
                }    
            }
            if (worst_enc == PEP_ct_pEp ||
                worst_sign == PEP_ct_pEp) {
                // No valid key was found for one or both; return a useful 
                // error comm_type
                PEP_comm_type error_ct = _MAX(error_enc, error_sign);    
                *comm_type = (error_ct == PEP_ct_unknown ? PEP_ct_key_b0rken : error_ct);
            }
            else {
                *comm_type = _MIN(max_comm_type, _MIN(worst_sign, worst_enc));
            }                
        }
        break;
    case GPG_ERR_ENOMEM:
        gpg.gpgme_op_keylist_end(session->ctx);
        *comm_type = PEP_ct_unknown;
        return PEP_OUT_OF_MEMORY;
    default:
        gpg.gpgme_op_keylist_end(session->ctx);
        return PEP_UNKNOWN_ERROR;
    };

    gpg.gpgme_op_keylist_end(session->ctx);

    return status;
}


static ssize_t _nullwriter(
        void *_handle,
        const void *buffer,
        size_t size
    )
{
    return size;
}

typedef struct _replace_only_uid_state {
    enum {
        replace_uid_command = 0,
        replace_uid_realname,
        replace_uid_email,
        replace_uid_comment,
        replace_uid_adduid_ok,
        replace_uid_select_for_delete,
        replace_uid_delete,
        replace_uid_delete_confirm,
        replace_uid_select_for_trust,
        replace_uid_trust,
        replace_uid_trust_ultimate,
        replace_uid_trust_ultimate_confirm,
        replace_uid_quit,
        replace_uid_save_okay,
        replace_uid_exit,
        replace_uid_error = -1
    } state;
const char *realname;
const char *email;
} replace_only_uid_state;


static gpgme_error_t replace_only_uid_fsm(
    void *_handle,
    gpgme_status_code_t statuscode,
    const char *args,
    int fd
)
{
    replace_only_uid_state *handle = _handle;
        
    switch (handle->state) {
        case replace_uid_command:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "adduid\n", 7);
                handle->state = replace_uid_realname;
            }
            break;
            
        case replace_uid_realname:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.name") == 0);
                assert(handle->realname);
                if (strcmp(args, "keygen.name") || !handle->realname) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                size_t realname_strlen = strlen(handle->realname);
                char* realname = (char*)calloc(1, realname_strlen + 2); // \n + \0
                if (!realname) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_ENOMEM;
                }
                strlcpy(realname, handle->realname, realname_strlen + 1);
                realname[realname_strlen] = '\n';
                gpg.gpgme_io_write(fd, realname, realname_strlen + 1);
                handle->state = replace_uid_email;
                free(realname);
            }
            break;
            
        case replace_uid_email:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.email") == 0);
                assert(handle->email);
                if (strcmp(args, "keygen.email") || !handle->email) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                size_t email_strlen = strlen(handle->email);
                char* email = (char*)calloc(1, email_strlen + 2); // \n + \0
                if (!email) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_ENOMEM;
                }
                strlcpy(email, handle->email, email_strlen + 1);
                email[email_strlen] = '\n';
                gpg.gpgme_io_write(fd, email, email_strlen + 1);
                handle->state = replace_uid_comment;
                free(email);
            }
            break;

        case replace_uid_comment:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.comment") == 0);
                if (strcmp(args, "keygen.comment") || !handle->email) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "\n", 1);
                //handle->state = replace_uid_adduid_ok;
                handle->state = replace_uid_select_for_delete;
            }
            break;
/*
        case replace_uid_adduid_ok:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.userid.cmd") == 0);
                if (strcmp(args, "keygen.userid.cmd")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "O\n", 2);
                handle->state = replace_uid_select_for_delete;
            }
            break;
	    */

        case replace_uid_select_for_delete:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "uid 1\n", 6);
                handle->state = replace_uid_delete;
            }
            break;

        case replace_uid_delete:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "deluid\n", 7);
                handle->state = replace_uid_delete_confirm;
            }
            break;

        case replace_uid_delete_confirm:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.remove.uid.okay") == 0);
                if (strcmp(args, "keyedit.remove.uid.okay")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = replace_uid_select_for_trust;
            }
            break;

        case replace_uid_select_for_trust:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "uid 1\n", 6);
                handle->state = replace_uid_trust;
            }
            break;

        case replace_uid_trust:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "trust\n", 6);
                handle->state = replace_uid_trust_ultimate;
            }
            break;

        case replace_uid_trust_ultimate:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "edit_ownertrust.value") == 0);
                if (strcmp(args, "edit_ownertrust.value")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "5\n", 2);
                handle->state = replace_uid_trust_ultimate_confirm;
            }
            break;

        case replace_uid_trust_ultimate_confirm:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "edit_ownertrust.set_ultimate.okay") == 0);
                if (strcmp(args, "edit_ownertrust.set_ultimate.okay")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = replace_uid_quit;
            }
            break;

        case replace_uid_quit:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "quit\n", 5);
                handle->state = replace_uid_save_okay;
            }
            break;

        case replace_uid_save_okay:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.save.okay") == 0);
                if (strcmp(args, "keyedit.save.okay")) {
                    handle->state = replace_uid_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = replace_uid_exit;
            }
            break;

        case replace_uid_exit:
            break;

        case replace_uid_error:
            return GPG_ERR_GENERAL;
            
        default:
            break;
    }
    return GPG_ERR_NO_ERROR;
}

PEP_STATUS pgp_replace_only_uid(
        PEP_SESSION session,
        const char* fpr,
        const char* realname,
        const char* email
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;
    gpgme_data_t output;
    replace_only_uid_state handle;

    assert(session);
    assert(fpr);
    assert(realname);
    assert(email);
    
    memset(&handle, 0, sizeof(replace_only_uid_state));
    handle.realname = realname;
    handle.email = email;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    struct gpgme_data_cbs data_cbs;
    memset(&data_cbs, 0, sizeof(struct gpgme_data_cbs));
    data_cbs.write = _nullwriter;
    gpg.gpgme_data_new_from_cbs(&output, &data_cbs, &handle);

    gpgme_error = _GPGERR(gpg.gpgme_op_edit(session->ctx, key, replace_only_uid_fsm, &handle,
            output));
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if(gpgme_error != GPG_ERR_NO_ERROR) {
        status = PEP_CANNOT_EDIT_KEY;
    }

    gpg.gpgme_data_release(output);
    gpg.gpgme_key_unref(key);

    return status;
}


typedef struct _renew_state {
    enum {
        renew_command = 0,
        renew_date,
        renew_secret_key,
        renew_command2,
        renew_date2,
        renew_quit,
        renew_save,
        renew_exit,
        renew_error = -1
    } state;
    const char *date_ref;
} renew_state;

static gpgme_error_t renew_fsm(
        void *_handle,
        gpgme_status_code_t statuscode,
        const char *args,
        int fd
    )
{
    renew_state *handle = _handle;

    switch (handle->state) {
        case renew_command:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "expire\n", 7);
                handle->state = renew_date;
            }
            break;

        case renew_date:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.valid") == 0);
                if (strcmp(args, "keygen.valid")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, handle->date_ref, 11);
                handle->state = renew_secret_key;
            }
            break;

        case renew_secret_key:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "key 1\n", 6);
                handle->state = renew_command2;
            }
            break;

        case renew_command2:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "expire\n", 7);
                handle->state = renew_date2;
            }
            break;

        case renew_date2:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keygen.valid") == 0);
                if (strcmp(args, "keygen.valid")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, handle->date_ref, 11);
                handle->state = renew_quit;
            }
            break;

        case renew_quit:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "quit\n", 5);
                handle->state = renew_save;
            }
            break;

        case renew_save:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.save.okay") == 0);
                if (strcmp(args, "keyedit.save.okay")) {
                    handle->state = renew_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = renew_exit;
            }
            break;

        case renew_exit:
            break;

        case renew_error:
            return GPG_ERR_GENERAL;
    }

    return GPG_ERR_NO_ERROR;
}


PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;
    gpgme_data_t output;
    renew_state handle;
    char date_text[12];

    assert(session);
    assert(fpr);

    memset(&handle, 0, sizeof(renew_state));
    snprintf(date_text, 12, "%.4d-%.2d-%.2d\n", ts->tm_year + 1900,
            ts->tm_mon + 1, ts->tm_mday);
    handle.date_ref = date_text;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    struct gpgme_data_cbs data_cbs;
    memset(&data_cbs, 0, sizeof(struct gpgme_data_cbs));
    data_cbs.write = _nullwriter;
    gpg.gpgme_data_new_from_cbs(&output, &data_cbs, &handle);

    gpgme_error = _GPGERR(gpg.gpgme_op_edit(session->ctx, key, renew_fsm, &handle,
            output));
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if(gpgme_error != GPG_ERR_NO_ERROR) {
        status = PEP_CANNOT_EDIT_KEY;
    }

    gpg.gpgme_data_release(output);
    gpg.gpgme_key_unref(key);

    return status;
}

typedef struct _revoke_state {
    enum {
        revoke_command = 0,
        revoke_approve,
        revoke_reason_code,
        revoke_reason_text,
        revoke_reason_ok,
        revoke_quit,
        revoke_save,
        revoke_exit,
        revoke_error = -1
    } state;
    const char *reason_ref;
} revoke_state;


/*** unused?
static bool isemptystring(const char *str)
{
    if (str == NULL)
        return true;

    for (; str; str++) {
        if (*str != ' ' && *str != '\t' && *str != '\n')
            return false;
    }

    return true;
}
***/


static gpgme_error_t revoke_fsm(
        void *_handle,
        gpgme_status_code_t statuscode,
        const char *args,
        int fd
    )
{
    revoke_state *handle = _handle;

    switch (handle->state) {
        case revoke_command:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "revkey\n", 7);
                handle->state = revoke_approve;
            }
            break;

        case revoke_approve:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.revoke.subkey.okay") == 0);
                if (strcmp(args, "keyedit.revoke.subkey.okay")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = revoke_reason_code;
            }
            break;

        case revoke_reason_code:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "ask_revocation_reason.code") == 0);
                if (strcmp(args, "ask_revocation_reason.code")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "1\n", 2);
                handle->state = revoke_reason_text;
            }
            break;

        case revoke_reason_text:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "ask_revocation_reason.text") == 0);
                if (strcmp(args, "ask_revocation_reason.text")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                // BUG: issues when reason given
                // Assertion failed: (gpg->cmd.code), function command_handler,
                // file engine-gpg.c, line 662.
                //
                // if (isemptystring(handle->reason_ref)) {
                    gpg.gpgme_io_write(fd, "\n", 1);
                // }
                // else {
                //     size_t len = strlen(handle->reason_ref);
                //     gpg.gpgme_io_write(fd, handle->reason_ref, len);
                //     if (handle->reason_ref[len - 1] == '\n')
                //         gpg.gpgme_io_write(fd, "\n", 1);
                //     else
                //         gpg.gpgme_io_write(fd, "\n\n", 2);
                // }
                handle->state = revoke_reason_ok;
            }
            break;

        case revoke_reason_ok:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "ask_revocation_reason.okay") == 0);
                if (strcmp(args, "ask_revocation_reason.okay")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = revoke_quit;
            }
            break;

        case revoke_quit:
            if (statuscode == GPGME_STATUS_GET_LINE) {
                assert(strcmp(args, "keyedit.prompt") == 0);
                if (strcmp(args, "keyedit.prompt")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "quit\n", 5);
                handle->state = revoke_save;
            }
            break;

        case revoke_save:
            if (statuscode == GPGME_STATUS_GET_BOOL) {
                assert(strcmp(args, "keyedit.save.okay") == 0);
                if (strcmp(args, "keyedit.save.okay")) {
                    handle->state = revoke_error;
                    return GPG_ERR_GENERAL;
                }
                gpg.gpgme_io_write(fd, "Y\n", 2);
                handle->state = revoke_exit;
            }
            break;

        case revoke_exit:
            break;

        case revoke_error:
            return GPG_ERR_GENERAL;
    }

    return GPG_ERR_NO_ERROR;
}

PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;
    gpgme_data_t output;
    revoke_state handle;

    assert(session);
    assert(fpr);

    memset(&handle, 0, sizeof(revoke_state));
    handle.reason_ref = reason;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    struct gpgme_data_cbs data_cbs;
    memset(&data_cbs, 0, sizeof(struct gpgme_data_cbs));
    data_cbs.write = _nullwriter;
    gpg.gpgme_data_new_from_cbs(&output, &data_cbs, &handle);

    gpgme_error = _GPGERR(gpg.gpgme_op_edit(session->ctx, key, revoke_fsm, &handle,
            output));
    assert(gpgme_error == GPG_ERR_NO_ERROR);
    if(gpgme_error != GPG_ERR_NO_ERROR) {
        status = PEP_CANNOT_EDIT_KEY;
    }

    gpg.gpgme_data_release(output);
    gpg.gpgme_key_unref(key);

    return status;
}

PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(expired);

    *expired = false;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    if ((key && key->expired) ||
        (key && key->subkeys && key->subkeys->expired))
    {
        // Already marked expired
        *expired = 1;
    }
    else if (key)
    {
        // Detect if will be expired
        // i.e. Check that keys capabilities will
        // not be expired at given time.
        gpgme_subkey_t _sk;
        bool crt_available = false;
        bool sgn_available = false;
        bool enc_available = false;
        for (_sk = key->subkeys; _sk; _sk = _sk->next) {
            if (_sk->expires > when || _sk->expires == 0) // not expired at that date ?
                                                          // Also, zero means "does not expire"
            {
                if (_sk->can_certify) crt_available = true;
                if (_sk->can_sign) sgn_available = true;
                if (_sk->can_encrypt) enc_available = true;
                // Authenticate is not used here.
            }
        }
        if(!(crt_available && sgn_available && enc_available))
        {
            *expired = 1;
        }
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
    }

    gpg.gpgme_key_unref(key);
    return status;
}

PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(revoked);

    *revoked = false;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    if (key && key->subkeys)
    {
        *revoked = key->subkeys->revoked;
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
    }

    gpg.gpgme_key_unref(key);
    return status;
}

PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(created);

    *created = 0;

    status = find_single_key(session, fpr, &key);
    if (status != PEP_STATUS_OK)
        return status;

    if (key && key->subkeys)
    {
        *created = (time_t) key->subkeys->timestamp;
    }
    else
    {
        status = PEP_KEY_NOT_FOUND;
    }

    gpg.gpgme_key_unref(key);
    return status;
}

PEP_STATUS pgp_binary(const char **path)
{
    assert(path);
    if (path == NULL)
        return PEP_ILLEGAL_VALUE;

    *path = NULL;

    gpgme_engine_info_t info;
    gpgme_error_t err = _GPGERR(gpg.gpgme_get_engine_info(&info));
    assert(err == GPG_ERR_NO_ERROR);
    if (err != GPG_ERR_NO_ERROR)
        return PEP_OUT_OF_MEMORY;

    *path = info->file_name;

    return PEP_STATUS_OK;
}

PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
        bool *has_private) {
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_key_t output_key;
    gpgme_error_t gpgerr = gpg.gpgme_get_key(session->ctx, fpr, &output_key, true);
    *has_private = false;
    switch (_GPGERR(gpgerr)) {
        case GPG_ERR_EOF:
        case GPG_ERR_INV_VALUE:
            status = PEP_KEY_NOT_FOUND;
            break;
        case GPG_ERR_AMBIGUOUS_NAME:
            status = PEP_KEY_HAS_AMBIG_NAME;
            break;
        case GPG_ERR_NO_ERROR:
            *has_private = true;
            gpg.gpgme_key_release(output_key);
            break;
        case GPG_ERR_ENOMEM:
            status = PEP_OUT_OF_MEMORY;
            break;
        default:
            status = PEP_UNKNOWN_ERROR;
            break;
    }
    return status;
}

PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite)
{
    // functionaliy unsupported; use gpg.conf

    switch (suite) {
        case PEP_CIPHER_SUITE_DEFAULT:
            return PEP_STATUS_OK;
        default:
            return PEP_CANNOT_CONFIG;
    }
}