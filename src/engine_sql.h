#pragma once
/**
 * @internal
 * @file engine_sql.h
 * @brief functions to SQL statements and strings to feed into prepared statements
 */

#include "pEp_internal.h"

/* Initialisation and finalisation
 * ***************************************************************** */

PEP_STATUS pEp_sql_init(PEP_SESSION session);
PEP_STATUS pEp_sql_finalize(PEP_SESSION session,
                            bool is_this_the_last_session);

/* In order to guarantee that concurrent accesses to the management database,
   possibly from multiple threads, happen correctly and without having failures
   inside transactions, we surround SQL statements with
     BEGIN EXCLUSIVE TRANSACTION;
     ...
     COMMIT TRANSACTION or ROLLBACK TRANSACTION;
   The execution of BEGIN EXCLUSIVE TRANSACTION in C always happens in a loop
   that automatically retries until the lock is acquired.  This feature is
   implemented in sql_reliability.h .
   Acquiring the lock at the beginning of the exclusive transaction becomes the
   main contention point between threads.  Unfortunately there are cases in
   which acquiring the lock seems to loop forever, even if no other threads are
   racing.  As a last resort, after PEP_BACKOFF_TIMES_BEFORE_REFRESHING_DB
   consecutive failures to begin an exclusive transaction, we close and reopen
   the database connection, re-preparing every SQL statement.  After this
   "refresh" it becomes possible to begin an exclusive transaction again.
   This function implements refreshing.
   Notice that refreshing is only legitimate while the SQL statement we are
   failing to execute is BEGIN EXCLUSIVE TRANSACTION. */
PEP_STATUS pEp_refresh_database_connections(PEP_SESSION session);


/* Debugging
 * ***************************************************************** */

/* Return a written representation of the current SQL state for the management
   db in the pointed session, suitable for logging or printing.  The returned
   memory is session-local, and will remain valid until the next call to this
   same function with the same session.
   In case of any error this still returns a valid non-empty string. */
const char *pEp_sql_status_text(PEP_SESSION session);


/* Literal strings with queries, for SQL prepared statements
 * ***************************************************************** */

// increment this when patching DDL
#define _DDL_USER_VERSION "19"

/* The strings below are not always all used in a C file, so it is normal that
   a lot of these variables are unused: we do not want warnings, nor complicated
   attribute declrations for every variable. */
#define MAYBE_UNUSED __attribute__((__unused__))

/**  
 * @internal
 * Strings to feed into prepared statements: system database
 */
static const char *sql_trustword MAYBE_UNUSED =
        "select id, word from wordlist where lang = lower(?1) "
        "and id = ?2 ;";

/**  
 * @internal
 * Strings to feed into prepared statements: management database
 */
static const char *sql_begin_exclusive_transaction MAYBE_UNUSED =
        "BEGIN EXCLUSIVE TRANSACTION;";
static const char *sql_commit_transaction MAYBE_UNUSED =
        "COMMIT TRANSACTION;";
static const char *sql_rollback_transaction MAYBE_UNUSED =
        "ROLLBACK TRANSACTION;";

static const char *sql_log MAYBE_UNUSED =
        "insert into log (title, entity, description, comment)"
        "values (?1, ?2, ?3, ?4);";


// FIXME?: problems if we don't have a key for the user - we get nothing
// Also: we've never used pgp_keypair.flags before now, but it seems to me that
// having combination of those flags is a road to ruin. Changing this for now.
static const char *sql_get_identity MAYBE_UNUSED =
        "select identity.main_key_id,"
        "   (case when (identity.flags & 1024 = 0) then ifnull(identity.username, person.username) "
        "         else identity.username end),"
        "   comm_type, lang, identity.flags,"
//        "   identity.flags | pgp_keypair.flags,"
        "   is_own, pEp_version_major, pEp_version_minor, enc_format"
        "   from identity"
        "   join person on id = identity.user_id"
        "   left join pgp_keypair on fpr = identity.main_key_id"
        "   left join trust on id = trust.user_id"
        "       and pgp_keypair_fpr = identity.main_key_id"
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1)"
        "               else 0"
        "          end) = 1"
        "   and identity.user_id = ?2"
        "   order by is_own desc, "
        "   timestamp desc; ";

static const char *sql_get_identities_by_main_key_id MAYBE_UNUSED =
        "select address, identity.user_id,"
        "   (case when (identity.flags & 1024 = 0) then ifnull(identity.username, person.username) "
        "         else identity.username end),"
        "   comm_type, lang, identity.flags,"
//        "   identity.flags | pgp_keypair.flags,"
        "   is_own, pEp_version_major, pEp_version_minor, enc_format"
        "   from identity"
        "   join person on id = identity.user_id"
        "   left join pgp_keypair on fpr = identity.main_key_id"
        "   left join trust on id = trust.user_id"
        "       and pgp_keypair_fpr = identity.main_key_id"
        "   where identity.main_key_id = ?1"
        "   order by is_own desc, "
        "   timestamp desc; ";

static const char *sql_get_identity_without_trust_check MAYBE_UNUSED =
        "select identity.main_key_id,"
        "   (case when (identity.flags & 1024 = 0) then ifnull(identity.username, person.username) "
        "         else identity.username end),"
        "   lang, identity.flags, is_own, pEp_version_major, pEp_version_minor, enc_format"
        "   from identity"
        "   join person on id = identity.user_id"
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1)"
        "               else 0"
        "          end) = 1"
        "   and identity.user_id = ?2 "
        "   order by is_own desc, "
        "   timestamp desc; ";

static const char *sql_get_identities_by_address MAYBE_UNUSED =
        "select user_id, identity.main_key_id,"
        "   (case when (identity.flags & 1024 = 0) then ifnull(identity.username, person.username) "
        "         else identity.username end),"
        "   lang, identity.flags, is_own, pEp_version_major, pEp_version_minor, enc_format"
        "   from identity"
        "   join person on id = identity.user_id"
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1)"
        "               else 0"
        "          end) = 1 "
        "   order by is_own desc, "
        "   timestamp desc; ";

static const char *sql_get_identities_by_userid MAYBE_UNUSED =
        "select address, identity.main_key_id,"
        "   (case when (identity.flags & 1024 = 0) then ifnull(identity.username, person.username) "
        "         else identity.username end),"
        "    comm_type, lang, identity.flags,"
//        "    identity.flags | pgp_keypair.flags,"
        "    is_own, pEp_version_major, pEp_version_minor, enc_format"
        "    from identity"
        "    join person on id = identity.user_id"
        "    left join pgp_keypair on fpr = identity.main_key_id"
        "    left join trust on id = trust.user_id"
        "        and pgp_keypair_fpr = identity.main_key_id"
        "    where identity.user_id = ?1"
        "    order by is_own desc, "
        "    timestamp desc; ";

static const char *sql_replace_identities_fpr MAYBE_UNUSED =
        "update identity"
        "   set main_key_id = ?1 "
        "   where main_key_id = ?2 ;";

static const char* sql_set_default_identity_fpr MAYBE_UNUSED =
        "update identity set main_key_id = ?3 "
        "    where user_id = ?1 and address = ?2; ";

static const char *sql_get_default_identity_fpr MAYBE_UNUSED =
        "select main_key_id from identity"
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1) "
        "               else 0 "
        "          end) = 1 "
        "          and user_id = ?2 ;";

static const char *sql_remove_fpr_as_identity_default MAYBE_UNUSED =
        "update identity set main_key_id = NULL where main_key_id = ?1 ;";

static const char *sql_remove_fpr_as_user_default MAYBE_UNUSED =
        "update person set main_key_id = NULL where main_key_id = ?1 ;";

// Set person, but if already exist, only update.
// if main_key_id already set, don't touch.
static const char *sql_set_person MAYBE_UNUSED =
        "insert into person (id, username, lang, main_key_id)"
        "  values (?1, ?2, ?3, ?4) ;";

static const char *sql_update_person MAYBE_UNUSED =
        "update person "
        "   set username = ?2, "
        "       lang = ?3, "
        "       main_key_id =  "
        "           (select coalesce( "
        "               (select main_key_id from person where id = ?1), "
        "                upper(replace(?4,' ',''))))"
        "   where id = ?1 ;";

// Will cascade.
static const char *sql_delete_person MAYBE_UNUSED =
        "delete from person where id = ?1 ;";

static const char *sql_set_as_pEp_user MAYBE_UNUSED =
        "update person set is_pEp_user = 1 "
        "   where id = ?1 ; ";

static const char *sql_is_pEp_user MAYBE_UNUSED =
        "select is_pEp_user from person "
        "   where id = ?1 ; ";

static const char* sql_exists_person MAYBE_UNUSED =
        "select count(*) from person "
        "   where id = ?1 ;";

// This will cascade to identity and trust
static const char* sql_replace_userid MAYBE_UNUSED =
        "update person set id = ?1 "
        "   where id = ?2;";

// Hopefully this cascades and removes trust entries...
static const char *sql_delete_key MAYBE_UNUSED =
        "delete from pgp_keypair "
        "   where fpr = ?1 ; ";

static const char *sql_replace_main_user_fpr MAYBE_UNUSED =
        "update person "
        "   set main_key_id = ?1 "
        "   where id = ?2 ;";

static const char *sql_get_main_user_fpr MAYBE_UNUSED =
        "select main_key_id from person"
        "   where id = ?1 ;";

static const char *sql_replace_main_user_fpr_if_equal MAYBE_UNUSED =
        "update person "
        "   set main_key_id = ?1 "
        "   where id = ?2 and main_key_id = ?3;";

static const char *sql_refresh_userid_default_key MAYBE_UNUSED =
        "update person "
        "   set main_key_id = "
        "       (select identity.main_key_id from identity "
        "           join trust on trust.user_id = identity.user_id "
        "               and trust.pgp_keypair_fpr = identity.main_key_id "
        "           join person on person.id = identity.user_id "
        "       where identity.user_id = ?1 "
        "       order by trust.comm_type desc "
        "       limit 1) "
        "where id = ?1 ; ";

static const char *sql_set_pgp_keypair MAYBE_UNUSED =
        "insert or ignore into pgp_keypair (fpr) "
        "values (upper(replace(?1,' ',''))) ;";

static const char *sql_set_pgp_keypair_flags MAYBE_UNUSED =
        "update pgp_keypair set flags = "
        "    ((?1 & 65535) | (select flags from pgp_keypair "
        "                     where fpr = (upper(replace(?2,' ',''))))) "
        "    where fpr = (upper(replace(?2,' ',''))) ;";

static const char *sql_unset_pgp_keypair_flags MAYBE_UNUSED =
        "update pgp_keypair set flags = "
        "    ( ~(?1 & 65535) & (select flags from pgp_keypair"
        "                       where fpr = (upper(replace(?2,' ',''))))) "
        "    where fpr = (upper(replace(?2,' ',''))) ;";

static const char* sql_exists_identity_entry MAYBE_UNUSED =
        "select count(*) from identity "
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1)"
        "               else 0"
        "          end) = 1"
        "    and user_id = ?2;";

static const char *sql_set_identity_entry MAYBE_UNUSED =
        "insert into identity ("
        "       address, main_key_id, "
        "       user_id, "
        "       username, "
        "       flags, is_own,"
        "       pEp_version_major, pEp_version_minor"
        "   ) values ("
        "       ?1,"
        "       upper(replace(?2,' ','')),"
        "       ?3,"
        "       ?4,"
        "       ?5,"
        "       ?6,"
        "       ?7,"
        "       ?8 "
        "   );";

static const char* sql_update_identity_entry MAYBE_UNUSED =
        "update identity "
        "   set main_key_id = upper(replace(?2,' ','')), "
        "       username = coalesce(username, ?4), "
        "       flags = ?5, "
        "       is_own = ?6, "
        "       pEp_version_major = ?7, "
        "       pEp_version_minor = ?8 "
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1) "
        "               else 0 "
        "          end) = 1 "
        "          and user_id = ?3 ;";

static const char* sql_force_set_identity_username MAYBE_UNUSED =
        "update identity "
        "   set username = coalesce(username, ?3) "
        "   where (case when (address = ?1) then (1)"
        "               when (lower(address) = lower(?1)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1) "
        "               else 0 "
        "          end) = 1 "
        "          and user_id = ?2 ;";


// " (select"
// "   coalesce("
// "    (select flags from identity"
// "     where address = ?1 and"
// "           user_id = ?3),"
// "    0)"
// " ) | (?4 & 255)"
/* set_identity ignores previous flags, and doesn't filter machine flags */

static const char *sql_set_identity_flags MAYBE_UNUSED =
        "update identity set flags = "
        "    ((?1 & 65535) | (select flags from identity"
        "                    where (case when (address = ?2) then (1)"
        "                                when (lower(address) = lower(?2)) then (1)"
        "                                when (replace(lower(address),'.','') = replace(lower(?2),'.','')) then (1)"
        "                                else 0 "
        "                           end) = 1 "
        "                           and user_id = ?3)) "
        "   where (case when (address = ?2) then (1)"
        "               when (lower(address) = lower(?2)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?2),'.','')) then (1)"
        "               else 0"
        "          end) = 1"
        "          and user_id = ?3 ;";

static const char *sql_unset_identity_flags MAYBE_UNUSED =
        "update identity set flags = "
        "    ( ~(?1 & 65535) & (select flags from identity"
        "                    where (case when (address = ?2) then (1)"
        "                                when (lower(address) = lower(?2)) then (1)"
        "                                when (replace(lower(address),'.','') = replace(lower(?2),'.','')) then (1)"
        "                                else 0 "
        "                           end) = 1 "
        "                           and user_id = ?3)) "
        "   where (case when (address = ?2) then (1)"
        "               when (lower(address) = lower(?2)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?2),'.','')) then (1)"
        "               else 0"
        "          end) = 1"
        "          and user_id = ?3 ;";

static const char *sql_set_ident_enc_format MAYBE_UNUSED =
        "update identity "
        "   set enc_format = ?1 "
        "   where (case when (address = ?2) then (1)"
        "               when (lower(address) = lower(?2)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?2),'.','')) then (1) "
        "               else 0 "
        "          end) = 1 "
        "          and user_id = ?3 ;";

static const char *sql_set_protocol_version MAYBE_UNUSED =
        "update identity "
        "   set pEp_version_major = ?1, "
        "       pEp_version_minor = ?2 "
        "   where (case when (address = ?3) then (1)"
        "               when (lower(address) = lower(?3)) then (1)"
        "               when (replace(lower(address),'.','') = replace(lower(?3),'.','')) then (1) "
        "               else 0 "
        "          end) = 1 "
        "          and user_id = ?4 ;";

static const char *sql_upgrade_protocol_version_by_user_id MAYBE_UNUSED =
        "update identity "
        "   set pEp_version_major = ?1, "
        "       pEp_version_minor = ?2 "
        "       where user_id = ?3 "
        "           and (case when (pEp_version_major < ?1) then (1)"
        "                     when (pEp_version_major > ?1) then (0)"
        "                     when (pEp_version_minor < ?2) then (1)"
        "                     else 0 "
        "           end) = 1 ;";

static const char *sql_set_trust MAYBE_UNUSED =
        "insert into trust (user_id, pgp_keypair_fpr, comm_type) "
        "values (?1, upper(replace(?2,' ','')), ?3) ;";

static const char *sql_update_trust MAYBE_UNUSED =
        "update trust set comm_type = ?3 "
        "   where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ',''));";

static const char *sql_clear_trust_info MAYBE_UNUSED =
        "delete from trust "
        "   where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ',''));";

static const char *sql_update_trust_to_pEp MAYBE_UNUSED =
        "update trust set comm_type = comm_type + 71 "
        "   where (user_id = ?1 "
        "          and (case when (comm_type = 56) then (1) "
        "                    when (comm_type = 184) then (1) "
        "                    else 0"
        "               end) = 1); ";

static const char* sql_exists_trust_entry MAYBE_UNUSED =
        "select count(*) from trust "
        "   where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ',''));";

static const char *sql_update_trust_for_fpr MAYBE_UNUSED =
        "update trust "
        "set comm_type = ?1 "
        "where pgp_keypair_fpr = upper(replace(?2,' ','')) ;";

static const char *sql_get_trust MAYBE_UNUSED =
        "select comm_type from trust where user_id = ?1 "
        "and pgp_keypair_fpr = upper(replace(?2,' ','')) ;";

static const char *sql_get_trust_by_userid MAYBE_UNUSED =
        "select pgp_keypair_fpr, comm_type from trust where user_id = ?1 ";

static const char *sql_least_trust MAYBE_UNUSED =
        "select min(comm_type) from trust where"
        " pgp_keypair_fpr = upper(replace(?1,' ',''))"
        " and comm_type != 0;"; // ignores PEP_ct_unknown
// returns PEP_ct_unknown only when no known trust is recorded

static const char *sql_update_key_sticky_bit_for_user MAYBE_UNUSED =
        "update trust set sticky = ?1 "
        "   where user_id = ?2 and pgp_keypair_fpr = upper(replace(?3,' ','')) ;";

static const char *sql_is_key_sticky_for_user MAYBE_UNUSED =
        "select sticky from trust "
        "    where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ','')) ; ";

static const char *sql_mark_compromised MAYBE_UNUSED =
        "update trust not indexed set comm_type = 15"
        " where pgp_keypair_fpr = upper(replace(?1,' ','')) ;";

static const char *sql_languagelist MAYBE_UNUSED =
        "select i18n_language.lang, name, phrase"
        " from i18n_language join i18n_token using (lang) where i18n_token.id = 1000;" ;

static const char *sql_i18n_token MAYBE_UNUSED =
        "select phrase from i18n_token where lang = lower(?1) and id = ?2 ;";

// Own keys
// We only care if it's 0 or non-zero
static const char *sql_own_key_is_listed MAYBE_UNUSED =
        "select count(*) from ("
        "   select pgp_keypair_fpr from trust"
        "      join identity on trust.user_id = identity.user_id"
        "      where pgp_keypair_fpr = upper(replace(?1,' ',''))"
        "           and identity.is_own = 1"
        ");";

static const char *sql_is_own_address MAYBE_UNUSED =
        "select count(*) from ("
        "   select address from identity"
        "       where (case when (address = ?1) then (1)"
        "                   when (lower(address) = lower(?1)) then (1)"
        "                   when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1)"
        "                   else 0"
        "           end) = 1 "
        "           and identity.is_own = 1"
        ");";

static const char *sql_own_identities_retrieve MAYBE_UNUSED =
        "select address, identity.main_key_id, identity.user_id,"
        "   (case when (identity.flags & 1024 = 0) then ifnull(identity.username, person.username) "
        "         else identity.username end),"
        "   lang, identity.flags,"
//        "   identity.flags | pgp_keypair.flags,"
        "   pEp_version_major, pEp_version_minor"
        "   from identity"
        "   join person on id = identity.user_id"
        "   left join pgp_keypair on fpr = identity.main_key_id"
        "   left join trust on id = trust.user_id"
        "       and pgp_keypair_fpr = identity.main_key_id"
        "   where identity.is_own = 1"
        "       and (identity.flags & ?1) = 0;";

static const char *sql_own_keys_retrieve MAYBE_UNUSED =
        "select distinct pgp_keypair_fpr from trust"
        "   join identity on trust.user_id = identity.user_id"
        "   where identity.is_own = 1";

static const char* sql_get_user_default_key MAYBE_UNUSED =
        "select main_key_id from person"
        "   where id = ?1;";

static const char* sql_get_all_keys_for_user MAYBE_UNUSED =
        "select pgp_keypair_fpr from trust"
        "   where user_id = ?1; ";

static const char* sql_get_all_keys_for_identity MAYBE_UNUSED =
    /* ?1: address; ?2: user_id */
    "SELECT T.pgp_keypair_fpr "
    "  FROM Trust T "
    "  WHERE T.user_id = ?2 "
    "UNION "
    "SELECT P.main_key_id "
    "  FROM Person P "
    "  WHERE P.id = ?2 "
    "UNION "
    "SELECT I.main_key_id "
    "  FROM Identity I "
    "  WHERE I.address = ?1 AND I.user_id = ?2 ";

static const char* sql_get_default_own_userid MAYBE_UNUSED =
        "select id from person"
        "   join identity on id = identity.user_id"
        "   where identity.is_own = 1";

// Sequence
static const char *sql_sequence_value1 MAYBE_UNUSED =
        "insert or replace into sequences (name, value) "
        "values (?1, "
        "       (select coalesce((select value + 1 from sequences "
        "           where name = ?1), 1 ))); ";

static const char *sql_sequence_value2 MAYBE_UNUSED =
        "select value from sequences where name = ?1 ;";

// Revocation tracking
static const char *sql_set_revoked MAYBE_UNUSED =
        "insert or replace into revoked_keys ("
        "    revoked_fpr, replacement_fpr, revocation_date) "
        "values (upper(replace(?1,' ','')),"
        "        upper(replace(?2,' ','')),"
        "        ?3) ;";

static const char *sql_get_revoked MAYBE_UNUSED =
        "select revoked_fpr, revocation_date from revoked_keys"
        "    where replacement_fpr = upper(replace(?1,' ','')) ;";

static const char *sql_get_replacement_fpr MAYBE_UNUSED =
        "select replacement_fpr, revocation_date from revoked_keys"
        "    where revoked_fpr = upper(replace(?1,' ','')) ;";

static const char *sql_get_userid_alias_default MAYBE_UNUSED =
        "select default_id from alternate_user_id "
        "   where alternate_id = ?1 ; ";

// Revocation tracking
static const char *sql_add_mistrusted_key MAYBE_UNUSED =
        "insert or replace into mistrusted_keys (fpr) "
        "   values (upper(replace(?1,' ',''))) ;";

static const char *sql_delete_mistrusted_key MAYBE_UNUSED =
        "delete from mistrusted_keys where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_is_mistrusted_key MAYBE_UNUSED =
        "select count(*) from mistrusted_keys where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_add_userid_alias MAYBE_UNUSED =
        "insert or replace into alternate_user_id (alternate_id, default_id) "
        "values (?2, ?1) ;";

static const char *sql_add_into_social_graph MAYBE_UNUSED =
        "insert or replace into social_graph(own_userid, own_address, contact_userid) "
        "values (?1, ?2, ?3) ;";

static const char *sql_get_own_address_binding_from_contact MAYBE_UNUSED =
        "select own_address from social_graph where own_userid = ?1 and contact_userid = ?2 ;";

static const char *sql_set_revoke_contact_as_notified MAYBE_UNUSED =
        "insert or replace into revocation_contact_list(fpr, own_address, contact_id) values (?1, ?2, ?3) ;";

static const char *sql_get_contacted_ids_from_revoke_fpr MAYBE_UNUSED =
        "select * from revocation_contact_list where fpr = ?1 ;";

static const char *sql_was_id_for_revoke_contacted MAYBE_UNUSED =
        "select count(*) from revocation_contact_list where fpr = ?1 and own_address = ?2 and contact_id = ?3 ;";

static const char *sql_has_id_contacted_address MAYBE_UNUSED =
        "select count(*) from social_graph where own_address = ?1 and contact_userid = ?2 ;";

// We only need user_id and address, since in the main usage, we'll call update_identity
// on this anyway when sending out messages.
static const char *sql_get_last_contacted MAYBE_UNUSED =
        "select user_id, address from identity where datetime('now') < datetime(timestamp, '+14 days') ; ";

static const char *sql_create_group MAYBE_UNUSED =
        "insert into groups (group_id, group_address, manager_userid, manager_address) "
        "VALUES (?1, ?2, ?3, ?4) ;";

static const char *sql_enable_group MAYBE_UNUSED =
        "update groups set active = 1 "
        "   where group_id = ?1 and group_address = ?2 ;";

static const char *sql_disable_group MAYBE_UNUSED =
        "update groups set active = 0 "
        "   where group_id = ?1 and group_address = ?2 ;";

static const char *sql_exists_group_entry MAYBE_UNUSED =
        "select count(*) from groups "
        "   where group_id = ?1 and group_address = ?2;";
static const char *sql_group_add_member MAYBE_UNUSED =
        "insert or ignore into own_groups_members (group_id, group_address, member_id, member_address) "
        "    values (?1, ?2, ?3, ?4) ;";
static const char *sql_group_delete_member MAYBE_UNUSED =
        "delete from own_groups_members "
        "    where group_id = ?1 and  group_address = ?2 and "
        "          member_id = ?3 and member_address = ?4 ;";
static const char *sql_set_group_member_status MAYBE_UNUSED =
        "update own_groups_members set active_member = ?1 "
        "    where group_id = ?2 and group_address = ?3 and "
        "          member_id = ?4 and member_address = ?5; ";
static const char *sql_group_join MAYBE_UNUSED =
        "update own_memberships set have_joined = 1 "
        "    where group_id = ?1 and group_address = ?2 and "
        "          own_id = ?3 and own_address = ?4; ";
static const char *sql_leave_group MAYBE_UNUSED =
        "update own_memberships set have_joined = 0 "
        "    where group_id = ?1 and group_address = ?2 and "
        "          own_id = ?3 and own_address = ?4; ";
static const char *sql_get_all_members MAYBE_UNUSED =
        "select member_id, member_address, active_member from own_groups_members "
        "    where group_id = ?1 and group_address = ?2; ";
static const char *sql_get_active_members MAYBE_UNUSED =
        "select member_id, member_address from own_groups_members "
        "    where group_id = ?1 and group_address = ?2 and active_member = 1; ";
static const char *sql_get_group_manager MAYBE_UNUSED =
        "select manager_userid, manager_address from groups "
        "   where group_id = ?1 and group_address = ?2; ";
static const char *sql_is_invited_group_member MAYBE_UNUSED =
        "select count(*) from own_groups_members "
        "   where group_id = ?1 and group_address = ?2 and member_id = ?3 and member_address = ?4; ";
static const char *sql_is_active_group_member MAYBE_UNUSED =
        "select active_member from own_groups_members "
        "   where group_id = ?1 and group_address = ?2 and member_id = ?3 and member_address = ?4; ";
static const char *sql_get_all_groups MAYBE_UNUSED =
        "select group_id, group_address from own_memberships; ";
static const char *sql_get_active_groups MAYBE_UNUSED =
        "select group_id, group_address from own_memberships where have_joined = 1; ";
static const char *sql_add_own_membership_entry MAYBE_UNUSED =
        "insert or replace into own_memberships (group_id, group_address, own_id, own_address, have_joined) "
        "    values (?1, ?2, ?3, ?4, 0) ; ";
static const char *sql_is_group_active MAYBE_UNUSED =
        "select count(*) from groups "
        "   where group_id = ?1 and group_address = ?2 and active = 1; ";

// This below can return multiple entries for multiple idents in same group
// FIXME: decide what we really need here
static const char *sql_retrieve_own_membership_info_for_group MAYBE_UNUSED =
        "select own_id, own_address, have_joined "
        "    from own_memberships "
        "    inner join groups using (group_id, group_address) "
        "        where group_id = ?1 and group_address = ?2; ";

static const char *sql_retrieve_own_membership_info_for_group_and_ident
    MAYBE_UNUSED =
        "select have_joined, manager_userid, manager_address, active "
        "    from own_memberships "
        "    inner join groups using (group_id, group_address) "
        "        where group_id = ?1 and group_address = ?2 and own_id = ?3 and own_address = ?4; ";

// This will return all membership info for all identities
static const char *sql_retrieve_all_own_membership_info MAYBE_UNUSED =
        "select group_id, group_address, own_id, own_address, have_joined, manager_id, manager_address, active "
        "    from own_memberships "
        "    inner join using (group_id, group_address); ";

static const char* sql_get_own_membership_status MAYBE_UNUSED =
        "select have_joined from own_memberships "
        "    where group_id = ?1 and group_address = ?2 and "
        "          own_id = ?3 and own_address = ?4; ";
