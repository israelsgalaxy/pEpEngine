/**
 * @internal
 * @file engine_sql.c
 * @brief functions to prepare SQL statements
 */

#include "pEp_internal.h"
#include "engine_sql.h"

/* Prevent people from using obsolete feature macros thinking that they still
   work. */
#if defined(_PEP_SQLITE_DEBUG)
# error "Support for the _PEP_SQLITE_DEBUG macro has been remove.  Please do"
# error "not #define it."
#endif

// sql overloaded functions - modified from sqlite3.c
/**
 *  @internal
 *
 *  <!--       _sql_lower()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *ctx        sqlite3_context
 *  @param[in]    argc        int
 *  @param[in]    **argv      sqlite3_value
 *
 */
static void _sql_lower(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    const char *z2;
    int n;
    z2 = (char*)sqlite3_value_text(argv[0]);
    n = sqlite3_value_bytes(argv[0]);
    /* Verify that the call to _bytes() does not invalidate the _text() pointer */
    assert( z2==(char*)sqlite3_value_text(argv[0]) );
    if( z2 ){
        char *z1 = (char*)sqlite3_malloc(n+1);
        if( z1 ){
            for(int i=0; i<n; i++){
                char c = z2[i];
                char c_mod = c | 0x20;
                if (c_mod < 0x61 || c_mod > 0x7a)
                    c_mod = c;
                z1[i] = c_mod;
            }
            z1[n] = '\0';
            sqlite3_result_text(ctx, z1, n, sqlite3_free);
        }
    }
}

/**
 *  @internal
 *
 *  <!--       sql_trace_callback()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    trace_constant        unsigned
 *  @param[in]    *context_ptr          the session
 *  @param[in]    *P        void
 *  @param[in]    *X        void
 *
 */
__attribute__((unused))
static int sql_trace_callback (unsigned trace_constant,
                               void *session_as_context_ptr,
                               void* P,
                               void* X) {
    PEP_SESSION session = (PEP_SESSION) session_as_context_ptr;
    /* Avoid PEP_REQUIRE_ORELSE here.  The output would be very distracting,
       for no benefit. */
    switch (trace_constant) {
        case SQLITE_TRACE_STMT: {
            const char* X_str = (const char*) X;
            const char *text = sqlite3_expanded_sql((sqlite3_stmt*)P);
            if (!EMPTYSTR(X_str) && X_str[0] == '-' && X_str[1] == '-')
                LOG_TRACE("statement: %s", X_str);
            else if (text != NULL)
                LOG_TRACE("statement: %s", text);
            break;
        }
        case SQLITE_TRACE_ROW: {
            const char *text = sqlite3_expanded_sql((sqlite3_stmt*)P);
            if (text != NULL)
                LOG_TRACE("row: %s", text);
            break;
        }
        case SQLITE_TRACE_CLOSE:
            LOG_TRACE("close");
            break;
        default:
            LOG_TRACE("unexpected trace_constant %u", trace_constant);
            break;
    }
    return 0;
}

/**
 *  @internal
 *
 *  <!--       errorLogCallback()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *pArg        the pEp session
 *  @param[in]    iErrCode     int
 *  @param[in]    *zMsg        constchar
 *
 */
__attribute__((unused))
void errorLogCallback(void *session_as_pArt, int iErrCode, const char *zMsg){
    PEP_SESSION session = (PEP_SESSION) session_as_pArt;
    LOG_ERROR("(%d) %s", iErrCode, zMsg);
}

// TODO: refactor and generalise these two functions if possible.
/**
 *  @internal
 *
 *  <!--       db_contains_table()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            PEP_SESSION
 *  @param[in]    *table_name        constchar
 *
 */
static int db_contains_table(PEP_SESSION session, const char* table_name) {
    if (!session || !table_name)
        return -1;

    // Table names can't be SQL parameters, so we do it this way.

    // these two must be the same number.
    char sql_buf[500];
    const size_t max_q_len = 500;

    size_t t_size, q_size;

    const char* q1 = "SELECT name FROM sqlite_master WHERE type='table' AND name='{"; // 61
    const char* q2 = "}';";       // 3

    q_size = 64;
    t_size = strlen(table_name);

    size_t query_len = q_size + t_size + 1;

    if (query_len > max_q_len)
        return -1;

    strlcpy(sql_buf, q1, max_q_len);
    strlcat(sql_buf, table_name, max_q_len);
    strlcat(sql_buf, q2, max_q_len);

    sqlite3_stmt *stmt = NULL;

    int rc = SQLITE_OK;
    rc = pEp_sqlite3_prepare_v2_nonbusy_nonlocked(session, session->db, sql_buf, -1, &stmt, NULL);
    PEP_WEAK_ASSERT_ORELSE_RETURN(rc == SQLITE_OK, 1);

    int retval = 0;

    rc = pEp_sqlite3_step_nonbusy(session, stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_OK || rc == SQLITE_ROW) {
        retval = 1;
    }

    sqlite3_finalize(stmt);

    return retval;

}

/**
 *  @internal
 *
 *  <!--       table_contains_column()       -->
 *
 *  @brief        TODO
 *
 *  @param[in]    session        PEP_SESSION
 *  @param[in]    *table_name    constchar
 *  @param[in]    *col_name      constchar
 *
 */
static int table_contains_column(PEP_SESSION session, const char* table_name,
                                 const char* col_name) {
    PEP_REQUIRE_ORELSE_RETURN(session
                              && ! EMPTYSTR(table_name) && ! EMPTYSTR(col_name),
                              -1);

    // Table names can't be SQL parameters, so we do it this way.

    // these two must be the same number.
    char sql_buf[500];
    const size_t max_q_len = 500;

    size_t t_size, c_size, q_size;

    const char* q1 = "SELECT "; // 7
    const char* q2 = " from "; // 6
    const char* q3 = ";";       // 1

    q_size = 14;
    t_size = strlen(table_name);
    c_size = strlen(col_name);

    size_t query_len = q_size + c_size + t_size + 1;

    if (query_len > max_q_len)
        return -1;

    strlcpy(sql_buf, q1, max_q_len);
    strlcat(sql_buf, col_name, max_q_len);
    strlcat(sql_buf, q2, max_q_len);
    strlcat(sql_buf, table_name, max_q_len);
    strlcat(sql_buf, q3, max_q_len);

    sqlite3_stmt *stmt = NULL;

    int rc = SQLITE_OK;
    rc = pEp_sqlite3_prepare_v2_nonbusy_nonlocked(session, session->db, sql_buf, -1, &stmt, NULL);
    PEP_ASSERT(rc == SQLITE_OK
               /* expected when the column does not exist. */
               || rc == SQLITE_ERROR);

    int retval = 0;

    /* We cannot use pEp_sqlite3_step_nonbusy because this is used early on, at
       initialisation time. */
    do {
        rc = sqlite3_step(stmt);
        PEP_ASSERT(rc != SQLITE_LOCKED);
    } while (rc == SQLITE_BUSY);
    if (rc == SQLITE_DONE || rc == SQLITE_OK || rc == SQLITE_ROW) {
        retval = 1;
    }

    sqlite3_finalize(stmt);

    return retval;
}

#define _PEP_MAX_AFFECTED 5
/**
 *  @internal
 *
 *  <!--       repair_altered_tables()      --> 
 *
 *  @brief        TODO
 *
 *  @param[in]    session        PEP_SESSION
 *
 */
PEP_STATUS repair_altered_tables(PEP_SESSION session) {
    PEP_STATUS status = PEP_STATUS_OK;

    char* table_names[_PEP_MAX_AFFECTED] = {0};

    const char* sql_query = "select tbl_name from sqlite_master WHERE sql LIKE '%REFERENCES%' AND sql LIKE '%_old%';";
    sqlite3_stmt *stmt;
    pEp_sqlite3_prepare_v2_nonbusy_nonlocked(session, session->db, sql_query, -1, &stmt, NULL);
    int i = 0;
    int int_result = 0;
    while ((int_result = pEp_sqlite3_step_nonbusy(session, stmt)) == SQLITE_ROW && i < _PEP_MAX_AFFECTED) {
        table_names[i++] = strdup((const char*)(sqlite3_column_text(stmt, 0)));
    }

    sqlite3_finalize(stmt);

    if ((int_result != SQLITE_DONE && int_result != SQLITE_OK) || i > (_PEP_MAX_AFFECTED + 1)) {
        status = PEP_UNKNOWN_DB_ERROR;
        goto pEp_free;
    }

    for (i = 0; i < _PEP_MAX_AFFECTED; i++) {
        const char* table_name = table_names[i];
        if (!table_name)
            break;

        if (strcmp(table_name, "identity") == 0) {
            PEP_SQL_BEGIN_LOOP(int_result);
            int_result = sqlite3_exec(session->db,
                                      "PRAGMA foreign_keys=off;\n"
                                      "BEGIN TRANSACTION;\n"
                                      "create table _identity_new (\n"
                                      "   address text,\n"
                                      "   user_id text\n"
                                      "       references person (id)\n"
                                      "       on delete cascade on update cascade,\n"
                                      "   main_key_id text\n"
                                      "       references pgp_keypair (fpr)\n"
                                      "       on delete set null,\n"
                                      "   comment text,\n"
                                      "   flags integer default 0,\n"
                                      "   is_own integer default 0,\n"
                                      "   timestamp integer default (datetime('now')),\n"
                                      "   primary key (address, user_id)\n"
                                      ");\n"
                                      "INSERT INTO _identity_new SELECT * from identity;\n"
                                      "DROP TABLE identity;\n"
                                      "ALTER TABLE _identity_new RENAME TO identity;\n"
                                      "COMMIT;\n"
                                      "PRAGMA foreign_keys=on;"
                                      ,
                                      NULL,
                                      NULL,
                                      NULL
            );
            PEP_SQL_END_LOOP();
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "trust") == 0) {
            PEP_SQL_BEGIN_LOOP(int_result);
            int_result = sqlite3_exec(session->db,
                                      "PRAGMA foreign_keys=off;\n"
                                      "BEGIN TRANSACTION;\n"
                                      "create table _trust_new (\n"
                                      "   user_id text not null\n"
                                      "       references person (id)\n"
                                      "       on delete cascade on update cascade,\n"
                                      "   pgp_keypair_fpr text not null\n"
                                      "       references pgp_keypair (fpr)\n"
                                      "       on delete cascade,\n"
                                      "   comm_type integer not null,\n"
                                      "   comment text,\n"
                                      "   primary key (user_id, pgp_keypair_fpr)\n"
                                      ");\n"
                                      "INSERT INTO _trust_new SELECT * from trust;\n"
                                      "DROP TABLE trust;\n"
                                      "ALTER TABLE _trust_new RENAME TO trust;\n"
                                      "COMMIT;\n"
                                      "PRAGMA foreign_keys=on;"
                                      ,
                                      NULL,
                                      NULL,
                                      NULL
            );
            PEP_SQL_END_LOOP();
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "alternate_user_id") == 0) {
            PEP_SQL_BEGIN_LOOP(int_result);
            int_result = sqlite3_exec(session->db,
                                      "PRAGMA foreign_keys=off;\n"
                                      "BEGIN TRANSACTION;\n"
                                      "create table _alternate_user_id_new (\n"
                                      "    default_id text references person (id)\n"
                                      "       on delete cascade on update cascade,\n"
                                      "    alternate_id text primary key\n"
                                      ");\n"
                                      "INSERT INTO _alternate_user_id_new SELECT * from alternate_user_id;\n"
                                      "DROP TABLE alternate_user_id;\n"
                                      "ALTER TABLE _alternate_user_id_new RENAME TO alternate_user_id;\n"
                                      "COMMIT;\n"
                                      "PRAGMA foreign_keys=on;"
                                      ,
                                      NULL,
                                      NULL,
                                      NULL
            );
            PEP_SQL_END_LOOP();
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "revocation_contact_list") == 0) {
            PEP_SQL_BEGIN_LOOP(int_result);
            int_result = sqlite3_exec(session->db,
                                      "PRAGMA foreign_keys=off;\n"
                                      "BEGIN TRANSACTION;\n"
                                      "create table _revocation_contact_list_new (\n"
                                      "   fpr text not null references pgp_keypair (fpr)\n"
                                      "       on delete cascade,\n"
                                      "   contact_id text not null references person (id)\n"
                                      "       on delete cascade on update cascade,\n"
                                      "   timestamp integer default (datetime('now')),\n"
                                      "   PRIMARY KEY(fpr, contact_id)\n"
                                      ");\n"
                                      "INSERT INTO _revocation_contact_list_new SELECT * from revocation_contact_list;\n"
                                      "DROP TABLE revocation_contact_list;\n"
                                      "ALTER TABLE _revocation_contact_list_new RENAME TO revocation_contact_list;\n"
                                      "COMMIT;\n"
                                      "PRAGMA foreign_keys=on;"
                    ,
                                      NULL,
                                      NULL,
                                      NULL
            );
            PEP_SQL_END_LOOP();
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "social_graph")) {
            PEP_SQL_BEGIN_LOOP(int_result);
            int_result = sqlite3_exec(session->db,
                                      "PRAGMA foreign_keys=off;\n"
                                      "BEGIN TRANSACTION;\n"
                                      "create table _social_new (\n"
                                      "    own_userid text,\n"
                                      "    own_address text,\n"
                                      "    contact_userid text,\n"
                                      "    CONSTRAINT fk_own_identity\n"
                                      "       FOREIGN KEY(own_address, own_userid)\n"
                                      "       REFERENCES identity(address, user_id)\n"
                                      "       ON DELETE CASCADE ON UPDATE CASCADE\n"
                                      ");\n"
                                      "INSERT INTO _social_graph_new SELECT * from social_graph;\n"
                                      "DROP TABLE social_graph;\n"
                                      "ALTER TABLE _social_graph_new RENAME TO social_graph;\n"
                                      "COMMIT;\n"
                                      "PRAGMA foreign_keys=on;"
                    ,
                                      NULL,
                                      NULL,
                                      NULL
            );
            PEP_SQL_END_LOOP();
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
    }

    PEP_SQL_BEGIN_LOOP(int_result);
        int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_key_check;\n"
            ,
            NULL,
            NULL,
            NULL
        );
    PEP_SQL_END_LOOP();
    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    pEp_free:
    for (i = 0; i < _PEP_MAX_AFFECTED; i++) {
        free(table_names[i]);
    }
    return status;
}

/**
 *  @internal
 *
 *  <!--       upgrade_revoc_contact_to_13()       -->
 *
 *  @brief        TODO
 *
 *  @param[in]    session        PEP_SESSION
 *
 */
static PEP_STATUS upgrade_revoc_contact_to_13(PEP_SESSION session) {
    // I HATE SQLITE.
    PEP_STATUS status = PEP_STATUS_OK;
    int int_result = 0;

    // Ok, first we ADD the column so we can USE it.
    // We will end up propagating the "error" this first time
    // (one-to-one revoke-replace relationships), but since key reset
    // hasn't been used in production, this is not a customer-facing
    // issue.

    // Note: the check upfront is to deal with partially-upgraded DB issues
    if (!table_contains_column(session, "revocation_contact_list", "own_address")) {
        PEP_SQL_BEGIN_LOOP(int_result);
        int_result = sqlite3_exec(
                session->db,
                "alter table revocation_contact_list\n"
                "   add column own_address text;\n",
                NULL,
                NULL,
                NULL
        );
        PEP_SQL_END_LOOP();
        PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK,
                                      PEP_UNKNOWN_DB_ERROR);
    }

    // the best we can do here is search per address, since these
    // are no longer associated with an identity. For now, if we find
    // something we can't add an address to, we'll delete the record.
    // this should not, in the current environment, ever happen, but
    // since we need to make the address part of the primary key, it's
    // the right thing to do. sqlite does support null fields in a primary
    // key for a weird version compatibility reason, but that doesn't
    // mean we should use it, and we should be *safe*, not relying
    // on an implementation-specific quirk which might be sanely removed
    // in a future sqlite version.

    identity_list* id_list = NULL;

    sqlite3_stmt* tmp_own_id_retrieve = NULL;
    int sqlite_status = pEp_sqlite3_prepare_v2_nonbusy_nonlocked(session, session->db, sql_own_identities_retrieve, -1, &tmp_own_id_retrieve, NULL);
    PEP_ASSERT(sqlite_status == SQLITE_OK
               || /* Expected when Identity.Username does not exist. */
               sqlite_status == SQLITE_ERROR);
    if (sqlite_status == SQLITE_OK) {
        // Kludgey - put the stmt in temporarily, and then remove again, so less code dup.
        // FIXME LATER: refactor if possible, but... chicken and egg, and thiis case rarely happens.
        session->own_identities_retrieve = tmp_own_id_retrieve;
        status = own_identities_retrieve(session, &id_list);
        sqlite3_finalize(tmp_own_id_retrieve);
        session->own_identities_retrieve = NULL;
        if (!status || !id_list)
            return PEP_STATUS_OK; // it's empty AFAIK (FIXME)
    }

    identity_list* curr_own = id_list;

    sqlite3_stmt* update_revoked_w_addr_stmt = NULL;
    const char* sql_query = "update revocation_contact_list set own_address = ?1 where fpr = ?2;";
    sqlite_status = pEp_sqlite3_prepare_v2_nonbusy_nonlocked(session, session->db, sql_query, -1, &update_revoked_w_addr_stmt, NULL);
    if (sqlite_status != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    // Ok, go through and find any keys associated with this address
    for ( ; curr_own && curr_own->ident; curr_own = curr_own->next) {
        if (EMPTYSTR(curr_own->ident->address)) // shouldn't happen
            continue;
        stringlist_t* keylist = NULL;
        status = find_keys(session, curr_own->ident->address, &keylist);
        stringlist_t* curr_key = keylist;
        for ( ; curr_key && curr_key->value; curr_key = curr_key->next) {
            if (EMPTYSTR(curr_key->value))
                continue;

            // We just do this lazily - if this isn't a revoked key, it
            // won't do anything.
            sqlite3_bind_text(update_revoked_w_addr_stmt, 1, curr_own->ident->address, -1,
                              SQLITE_STATIC);
            sqlite3_bind_text(update_revoked_w_addr_stmt, 2, curr_key->value, -1,
                              SQLITE_STATIC);

            int_result = pEp_sqlite3_step_nonbusy(session, update_revoked_w_addr_stmt);
            PEP_ASSERT(int_result == SQLITE_DONE);

            sql_reset_and_clear_bindings(update_revoked_w_addr_stmt);

            if (int_result != SQLITE_DONE)
                return PEP_UNKNOWN_DB_ERROR;

        }
    }
    sqlite3_finalize(update_revoked_w_addr_stmt);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "delete from revocation_contact_list where own_address is NULL;\n"
            "PRAGMA foreign_keys=off;\n"
            "BEGIN TRANSACTION;\n"
            "create table if not exists _revocation_contact_list_new (\n"
            "   fpr text not null references pgp_keypair (fpr)\n"
            "       on delete cascade,\n"
            "   own_address text,\n"
            "   contact_id text not null references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   timestamp integer default (datetime('now')),\n"
            "   PRIMARY KEY(fpr, own_address, contact_id)\n"
            ");\n"
            "INSERT INTO _revocation_contact_list_new (fpr, "
            "                                          own_address, "
            "                                          contact_id) "
            "   SELECT revocation_contact_list.fpr, "
            "          revocation_contact_list.own_address, "
            "          revocation_contact_list.contact_id "
            "   FROM revocation_contact_list "
            "   WHERE 1;\n"
            "DROP TABLE revocation_contact_list;\n"
            "ALTER TABLE _revocation_contact_list_new RENAME TO revocation_contact_list;\n"
            "COMMIT;\n"
            "\n"
            "PRAGMA foreign_keys=on;\n"
            ,
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    return status;
}


/**
 *  @internal
 *
 *  <!--       user_version()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *_version     void
 *  @param[in]    count         int
 *  @param[in]    **text        char
 *  @param[in]    **name        char
 *
 */
static int user_version(void *_version, int count, char **text, char **name)
{
    if (!(_version && count == 1 && text && text[0]))
        return -1;

    int *version = (int *) _version;
    *version = atoi(text[0]);
    return 0;
}

static PEP_STATUS _create_initial_tables(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "create table if not exists version_info (\n"
            "   id integer primary key,\n"
            "   timestamp integer default (datetime('now')),\n"
            "   version text,\n"
            "   comment text\n"
            ");\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    // This string is now too large for the C standard, so we're going to break it up some.
    // I presume we use the enormous string for performance purposes... terrible for debugging purposes, but OK.
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA application_id = 0x23423423;\n"
            "create table if not exists log (\n"
            "   timestamp integer default (datetime('now')),\n"
            "   title text not null,\n"
            "   description text,\n"
            "   entity text not null,\n"
            "   comment text\n"
            ");\n"
            "create index if not exists log_timestamp on log (\n"
            "   timestamp\n"
            ");\n"
            ,
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _create_core_tables(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "create table if not exists pgp_keypair (\n"
            "   fpr text primary key,\n"
            "   created integer,\n"
            "   expires integer,\n"
            "   comment text,\n"
            "   flags integer default 0\n"
            ");\n"
            "create index if not exists pgp_keypair_expires on pgp_keypair (\n"
            "   expires\n"
            ");\n"
            "create table if not exists person (\n"
            "   id text primary key,\n"
            "   username text not null,\n"
            "   main_key_id text\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete set null,\n"
            "   lang text,\n"
            "   comment text,\n"
            //                "   device_group text,\n"
            "   is_pEp_user integer default 0\n"
            ");\n"
            "create table if not exists identity (\n"
            "   address text,\n"
            "   user_id text\n"
            "       references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   main_key_id text\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete set null,\n"
            "   username text,\n"
            "   comment text,\n"
            "   flags integer default 0,\n"
            "   is_own integer default 0,\n"
            "   pEp_version_major integer default 0,\n"
            "   pEp_version_minor integer default 0,\n"
            "   enc_format integer default 0,\n"
            "   timestamp integer default (datetime('now')),\n"
            "   primary key (address, user_id)\n"
            ");\n"
            "create index if not exists identity_userid on identity (user_id);\n"
            "create table if not exists trust (\n"
            "   user_id text not null\n"
            "       references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   pgp_keypair_fpr text not null\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete cascade,\n"
            "   comm_type integer not null,\n"
            "   comment text,\n"
            "   sticky integer default 0,\n"
            "   primary key (user_id, pgp_keypair_fpr)\n"
            ");\n"
            ,
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _create_group_tables(PEP_SESSION session) {
    if (!session)
        return PEP_ILLEGAL_VALUE;

    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            // group information
            "create table if not exists groups (\n"
            "   group_id text,\n"
            "   group_address text,\n"
            "   manager_userid text,\n"
            "   manager_address text,\n"
            "   active integer default 0,\n"
            "   constraint groups_pk\n"
            "       primary key (group_address, group_id),\n"
            "   constraint group_identity_fk\n"
            "       foreign key (group_address, group_id) references identity\n"
            "          on update cascade on delete cascade,\n"
            "   constraint manager_identity_fk\n"
            "       foreign key (manager_address, manager_userid) references identity\n"
            "          on update cascade on delete cascade\n"
            ");\n"
            "create table if not exists own_memberships (\n"
            "   group_id text,\n"
            "   group_address text,\n"
            "   own_id text,\n"
            "   own_address text,\n"
            "   have_joined int default 0,\n"
            "   constraint own_memberships_pk\n"
            "       primary key (group_address, group_id),\n"
            "   constraint own_memberships_own_id_fk\n"
            "       foreign key (own_address, own_id) references identity\n"
            "           on update cascade on delete cascade,\n"
            "   constraint own_memberships_group_fk\n"
            "       foreign key (group_address, group_id) references groups\n"
            "           on update cascade on delete cascade\n"
            ");\n"
            "create table if not exists own_groups_members (\n"
            "   group_id text,\n"
            "   group_address text,\n"
            "   member_id text,\n"
            "   member_address text,\n"
            "   active_member int default 0,\n"
            "   constraint own_groups_members_pk\n"
            "       primary key (group_address, group_id, member_address, member_id),\n"
            "   constraint group_ident_fk\n"
            "       foreign key (group_address, group_id) references groups\n"
            "           on update cascade on delete cascade,\n"
            "   constraint member_ident_fk\n"
            "       foreign key (member_address, member_id) references identity\n"
            "           on update cascade on delete cascade\n"
            ");\n"
            ,
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _create_supplementary_key_tables(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "create table if not exists revoked_keys (\n"
            "   revoked_fpr text primary key,\n"
            "   replacement_fpr text not null\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete cascade,\n"
            "   revocation_date integer\n"
            ");\n"
            // mistrusted keys
            "create table if not exists mistrusted_keys (\n"
            "    fpr text primary key\n"
            ");\n"
            // social graph for key resets
            "create table if not exists social_graph (\n"
            "    own_userid text,\n"
            "    own_address text,\n"
            "    contact_userid text,\n"
            "    CONSTRAINT fk_own_identity\n"
            "       FOREIGN KEY(own_address, own_userid)\n"
            "       REFERENCES identity(address, user_id)\n"
            "       ON DELETE CASCADE ON UPDATE CASCADE\n"
            ");\n"
            // list of user_ids sent revocation
            "create table if not exists revocation_contact_list (\n"
            "   fpr text not null references pgp_keypair (fpr)\n"
            "       on delete cascade,\n"
            "   own_address text,\n"
            "   contact_id text not null references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   timestamp integer default (datetime('now')),\n"
            "   PRIMARY KEY(fpr, own_address, contact_id)\n"
            ");\n"
            ,
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _create_misc_admin_tables(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
        session->db,
        // sequences
        "create table if not exists sequences(\n"
        "   name text primary key,\n"
        "   value integer default 0\n"
        ");\n"
        // user id aliases
        "create table if not exists alternate_user_id (\n"
        "    default_id text references person (id)\n"
        "       on delete cascade on update cascade,\n"
        "    alternate_id text primary key\n"
        ");\n"
        ,
        NULL,
        NULL,
        NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}


// The create tables string is now too large for the C standard, so we're going to break it up some.
// I presume we use the enormous string for performance purposes... terrible for debugging purposes, but OK.
PEP_STATUS create_tables(PEP_SESSION session) {

    if (!session)
        return PEP_ILLEGAL_VALUE;
    
    PEP_STATUS status = PEP_STATUS_OK;

    status = _create_initial_tables(session);
    if (status != PEP_STATUS_OK)
        return status;

    status = _create_core_tables(session);
    if (status != PEP_STATUS_OK)
        return status;

    status = _create_group_tables(session);
    if (status != PEP_STATUS_OK)
        return status;

    status = _create_supplementary_key_tables(session);
    if (status != PEP_STATUS_OK)
        return status;

    status = _create_misc_admin_tables(session);

    return status;
}

PEP_STATUS get_db_user_version(PEP_SESSION session, int* version) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "pragma user_version;",
            user_version,
            version,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

// Only called if input version is 1
static PEP_STATUS _verify_version(PEP_SESSION session, int* version) {
    // Sometimes the user_version wasn't set correctly.
    bool version_changed = true;
    int int_result __attribute__((__unused__));
    if (table_contains_column(session, "identity", "username")) {
        *version = 17;
    }
    else if (table_contains_column(session, "trust", "sticky")) {
        *version = 16;
    }
    else if (table_contains_column(session, "groups", "group_identity")) {
        *version = 15;
    }
    else if (table_contains_column(session, "identity", "enc_format")) {
        *version = 14;
    }
    else if (table_contains_column(session, "revocation_contact_list", "own_address")) {
        *version = 13;
    }
    else if (table_contains_column(session, "identity", "pEp_version_major")) {
        *version = 12;
    }
    else if (db_contains_table(session, "social_graph") > 0) {
        if (!table_contains_column(session, "person", "device_group"))
            *version = 10;
        else
            *version = 9;
    }
    else if (table_contains_column(session, "identity", "timestamp") > 0) {
        *version = 8;
    }
    else if (table_contains_column(session, "person", "is_pEp_user") > 0) {
        *version = 7;
    }
    else if (table_contains_column(session, "identity", "is_own") > 0) {
        *version = 6;
    }
    else if (table_contains_column(session, "pgp_keypair", "flags") > 0) {
        *version = 2;
    }
    else {
        version_changed = false;
    }

    if (version_changed) {
        // set it in the DB, finally. Yeesh.
        char verbuf[21]; // enough digits for a max-sized 64 bit int, cmon.
        sprintf(verbuf, "%d", *version);

        size_t query_size = strlen(verbuf) + 25;
        char *query = calloc(query_size, 1);

        strlcpy(query, "pragma user_version = ", query_size);
        strlcat(query, verbuf, query_size);
        strlcat(query, ";", query_size);

        PEP_SQL_BEGIN_LOOP(int_result);
        int_result = sqlite3_exec(
                session->db,
                query,
                user_version,
                &*version,
                NULL
        );
        PEP_SQL_END_LOOP();
        free(query);
    }

    // FIXME: status
    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_2(PEP_SESSION session) {
    // N.B. addition of device_group column removed in DDL v10
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "alter table pgp_keypair\n"
            "   add column flags integer default 0;\n",
            // "alter table person\n"
            // "   add column device_group text;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_5(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "delete from pgp_keypair where fpr = '';",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "delete from trust where pgp_keypair_fpr = '';",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_6(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "alter table identity\n"
            "   add column is_own integer default 0;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "update identity\n"
            "   set is_own = 1\n"
            "   where (user_id = '" PEP_OWN_USERID "');\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    // Turns out that just adding "on update cascade" in
    // sqlite is a PITA. We need to be able to cascade
    // person->id replacements (for temp ids like "TOFU_")
    // so here we go...
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_keys=off;\n"
            "BEGIN TRANSACTION;\n"
            "create table _identity_new (\n"
            "   address text,\n"
            "   user_id text\n"
            "       references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   main_key_id text\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete set null,\n"
            "   comment text,\n"
            "   flags integer default 0,\n"
            "   is_own integer default 0,\n"
            "   primary key (address, user_id)\n"
            ");\n"
            "INSERT INTO _identity_new SELECT * FROM identity;\n"
            "DROP TABLE identity;\n"
            "ALTER TABLE _identity_new RENAME TO identity;\n"
            "COMMIT;\n"
            "\n"
            "BEGIN TRANSACTION;\n"
            "create table _trust_new (\n"
            "   user_id text not null\n"
            "       references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   pgp_keypair_fpr text not null\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete cascade,\n"
            "   comm_type integer not null,\n"
            "   comment text,\n"
            "   primary key (user_id, pgp_keypair_fpr)\n"
            ");\n"
            "INSERT INTO _trust_new SELECT * FROM trust;\n"
            "DROP TABLE trust;\n"
            "ALTER TABLE _trust_new RENAME TO trust;\n"
            "COMMIT;\n"
            "\n"
            "PRAGMA foreign_keys=on;\n"
            "create table if not exists alternate_user_id (\n"
            "    default_id text references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "    alternate_id text primary key\n"
            ");\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_key_check;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    // FIXME: foreign key check here

    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);
    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_7(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "alter table person\n"
            "   add column is_pEp_user integer default 0;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "update person\n"
            "   set is_pEp_user = 1\n"
            "   where id = "
            "       (select distinct id from person "
            "               join trust on id = user_id "
            "               where (case when (comm_type = 127) then (id) "
            "                           when (comm_type = 255) then (id) "
            "                           else 0"
            "                      end) = id );\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "create table if not exists mistrusted_keys (\n"
            "    fpr text primary key\n"
            ");\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_8(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_keys=off;\n"
            "BEGIN TRANSACTION;\n"
            "create table _identity_new (\n"
            "   address text,\n"
            "   user_id text\n"
            "       references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   main_key_id text\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete set null,\n"
            "   comment text,\n"
            "   flags integer default 0,\n"
            "   is_own integer default 0,\n"
            "   timestamp integer default (datetime('now')),\n"
            "   primary key (address, user_id)\n"
            ");\n"
            "INSERT INTO _identity_new (address, user_id, main_key_id, "
            "                      comment, flags, is_own) "
            "   SELECT identity.address, identity.user_id, "
            "          identity.main_key_id, identity.comment, "
            "          identity.flags, identity.is_own "
            "   FROM identity "
            "   WHERE 1;\n"
            "DROP TABLE identity;\n"
            "ALTER TABLE _identity_new RENAME TO identity;\n"
            "COMMIT;\n"
            "\n"
            "PRAGMA foreign_keys=on;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_key_check;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    // FIXME: foreign key check
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}


static PEP_STATUS _upgrade_DB_to_ver_9(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "create table if not exists social_graph (\n"
            "    own_userid text,\n"
            "    own_address text,\n"
            "    contact_userid text,\n"
            "    CONSTRAINT fk_own_identity\n"
            "       FOREIGN KEY(own_address, own_userid)\n"
            "       REFERENCES identity(address, user_id)\n"
            "       ON DELETE CASCADE ON UPDATE CASCADE\n"
            ");\n"
            "create table if not exists revocation_contact_list (\n"
            "   fpr text not null references pgp_keypair (fpr)\n"
            "       on delete cascade,\n"
            "   contact_id text not null references person (id)\n"
            "       on delete cascade on update cascade,\n"
            "   timestamp integer default (datetime('now')),\n"
            "   PRIMARY KEY(fpr, contact_id)\n"
            ");\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_10(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_keys=off;\n"
            "BEGIN TRANSACTION;\n"
            "create table _person_new (\n"
            "   id text primary key,\n"
            "   username text not null,\n"
            "   main_key_id text\n"
            "       references pgp_keypair (fpr)\n"
            "       on delete set null,\n"
            "   lang text,\n"
            "   comment text,\n"
            "   is_pEp_user integer default 0\n"
            ");\n"
            "INSERT INTO _person_new (id, username, main_key_id, "
            "                    lang, comment, is_pEp_user) "
            "   SELECT person.id, person.username, "
            "          person.main_key_id, person.lang, "
            "          person.comment, person.is_pEp_user "
            "   FROM person "
            "   WHERE 1;\n"
            "DROP TABLE person;\n"
            "ALTER TABLE _person_new RENAME TO person;\n"
            "COMMIT;\n"
            "\n"
            "PRAGMA foreign_keys=on;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "PRAGMA foreign_key_check;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _force_upgrade_own_latest_protocol_version(PEP_SESSION session) {
    PEP_REQUIRE(session != NULL);

    PEP_STATUS status = PEP_STATUS_OK;
#define OUT_OF_MEMORY                \
    do {                             \
        status = PEP_OUT_OF_MEMORY;  \
        goto end;                    \
    } while (false)

    // N.B. WE DEFINE PEP_VERSION - MAJOR OR MINOR VERSIONS MUST NOT BE TOO LONG.
#define VERSION_DIGIT_NO 10
    char major_buf[VERSION_DIGIT_NO];
    char minor_buf[VERSION_DIGIT_NO];

    int int_result = SQLITE_OK;
    char *version_upgrade_stmt = NULL;

    // Guess we were abusing sscanf here, so we'll do it this way:
    const char *cptr = PEP_PROTOCOL_VERSION;
    size_t major_len = 0;
    size_t minor_len = 0;

    char *bufptr = major_buf;
    while (*cptr != '.' && *cptr != '\0') {
        if (major_len == VERSION_DIGIT_NO)
            OUT_OF_MEMORY;
        *bufptr++ = *cptr++;
        major_len++;
    }
    *bufptr = '\0';
    bufptr = minor_buf;

    if (*cptr == '.') {
        cptr++;
        while (*cptr != '\0') {
            if (minor_len == VERSION_DIGIT_NO)
                OUT_OF_MEMORY;
            *bufptr++ = *cptr++;
            minor_len++;
        }
    } else {
        *bufptr++ = '0';
    }
    *bufptr = '\0';

    const char *version_upgrade_startstr =
            "update identity\n"
            "    set pEp_version_major = ";
    const char *version_upgrade_midstr = ",\n"
                                 "        pEp_version_minor = ";
    const char *version_upgrade_endstr =
            "\n"
            "    where identity.is_own = 1;\n"; // FIXME: Group idents?

    size_t new_stringlen = strlen(version_upgrade_startstr) + major_len +
                           strlen(version_upgrade_midstr) + minor_len +
                           strlen(version_upgrade_endstr);

    version_upgrade_stmt = calloc(new_stringlen + 1, 1);
    if (version_upgrade_stmt == NULL)
        OUT_OF_MEMORY;
    snprintf(version_upgrade_stmt, new_stringlen + 1, "%s%s%s%s%s",
             version_upgrade_startstr, major_buf, version_upgrade_midstr, minor_buf, version_upgrade_endstr);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            version_upgrade_stmt,
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();

 end:
    free(version_upgrade_stmt);
    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    return status;
#undef OUT_OF_MEMORY
#undef VERSION_DIGIT_NO
}

static PEP_STATUS _upgrade_DB_to_ver_12(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "create index if not exists identity_userid_addr on identity(address, user_id);\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "alter table identity\n"
            "   add column pEp_version_major integer default 0;\n"
            "alter table identity\n"
            "   add column pEp_version_minor integer default 0;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "update identity\n"
            "   set pEp_version_major = 2,\n"
            "       pEp_version_minor = 1\n"
            "   where exists (select * from person\n"
            "                     where identity.user_id = person.id\n"
            "                     and identity.is_own = 0\n"
            "                     and person.is_pEp_user = 1);\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
    // Superceded by the -to-version-18 upgrade.
//    return _force_upgrade_own_latest_protocol_version(session);
}

static PEP_STATUS _upgrade_DB_to_ver_14(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "alter table identity\n"
            "   add column enc_format integer default 0;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_15(PEP_SESSION session) {
    return _create_group_tables(session);
}

static PEP_STATUS _upgrade_DB_to_ver_16(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
        session->db,
        "alter table trust\n"
        "   add column sticky integer default 0;\n",
        NULL,
        NULL,
        NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

static PEP_STATUS _upgrade_DB_to_ver_17(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "alter table identity\n"
            "   add column username;\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

// Version 2.0 and earlier will now no longer be supported with other
// pEp users.
static PEP_STATUS _upgrade_DB_to_ver_18(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            "update identity\n"
            "   set pEp_version_major = 2,\n"
            "       pEp_version_minor = 1\n"
            "   where exists (select * from person\n"
            "                     where identity.user_id = person.id\n"
            "                     and identity.pEp_version_major = 2\n"
            "                     and identity.pEp_version_minor = 0\n"
            "                     and person.is_pEp_user = 1);\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return _force_upgrade_own_latest_protocol_version(session);
}

static PEP_STATUS _upgrade_DB_to_ver_19(PEP_SESSION session) {
    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
            session->db,
            /* This index was useless: it was an index on the (multi-column)
               primary key, always implemented using an index which gets also
               used in queries. */
            "drop index if exists identity_userid_addr;\n"
            "\n"
            "create index if not exists identity_userid on identity (user_id);\n",
            NULL,
            NULL,
            NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

// Honestly, the upgrades should be redone in a transaction IMHO.
static PEP_STATUS _check_and_execute_upgrades(PEP_SESSION session, int version) {
    PEP_STATUS status = PEP_STATUS_OK;

    switch(version) {
        case 1:
            status = _upgrade_DB_to_ver_2(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 2:
        case 3:
        case 4:
            status = _upgrade_DB_to_ver_5(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 5:
            status = _upgrade_DB_to_ver_6(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 6:
            status = _upgrade_DB_to_ver_7(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 7:
            status = _upgrade_DB_to_ver_8(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 8:
            status = _upgrade_DB_to_ver_9(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 9:
            if (version > 1) {
                status = _upgrade_DB_to_ver_10(session);
                if (status != PEP_STATUS_OK)
                    return status;
            }
        case 10:
            status = repair_altered_tables(session);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK)
                return status;
        case 11:
            status = _upgrade_DB_to_ver_12(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 12:
            status = upgrade_revoc_contact_to_13(session);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK)
                return status;
        case 13:
            status = _upgrade_DB_to_ver_14(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 14:
            status = _upgrade_DB_to_ver_15(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 15:
            status = _upgrade_DB_to_ver_16(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 16:
            status = _upgrade_DB_to_ver_17(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 17:
            status = _upgrade_DB_to_ver_18(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 18:
            status = _upgrade_DB_to_ver_19(session);
            if (status != PEP_STATUS_OK)
                return status;
        case 19:
            break;
        default:
            return PEP_ILLEGAL_VALUE;
    }
    return PEP_STATUS_OK;
}

static int pEp_open_local_database(PEP_SESSION session,
                                   int other_flags) {
    PEP_ASSERT(! EMPTYSTR(LOCAL_DB));
    PEP_ASSERT(session->db == NULL);
    return sqlite3_open_v2(LOCAL_DB,
                           & session->db,
                           SQLITE_OPEN_READWRITE
                           | SQLITE_OPEN_FULLMUTEX
                           | SQLITE_OPEN_PRIVATECACHE
                           | other_flags,
                           NULL);
}

/* Forward declaration. */
static PEP_STATUS _prepare_sql_stmts(PEP_SESSION session);

PEP_STATUS pEp_sql_init(PEP_SESSION session) {
    PEP_REQUIRE(session);
    PEP_STATUS status = PEP_STATUS_OK;
    bool very_first __attribute__((__unused__)) = false;

#define FAIL(the_status)        \
    do {                        \
        status = (the_status);  \
        goto end;               \
    } while (false)

    /* Sanity check.  If this sqlite3 is not thread safe refuse to do
       anything. */
    if (! sqlite3_threadsafe()) {
        LOG_CRITICAL("this SQLite3 is not thread-safe and cannot be used");
        return PEP_INIT_SQLITE3_WITHOUT_MUTEX;
    }

    /* Open a database connection. */
    int int_result = SQLITE_OK;
    int_result = pEp_open_local_database(session,
                                         (session->first_session_at_init_time
                                          ? SQLITE_OPEN_CREATE
                                          : 0));
    if (int_result != SQLITE_OK)
        FAIL(PEP_INIT_CANNOT_OPEN_DB);

    /* Make the schema, when needed. */
    int version = 0;
    if (session->first_session_at_init_time) {
        status = create_tables(session);
        if (status != PEP_STATUS_OK)
            FAIL(status);
        status = get_db_user_version(session, &version);
        if (status != PEP_STATUS_OK)
            FAIL(status);
    }

    void (*xFunc_lower)(sqlite3_context *, int, sqlite3_value **) = &_sql_lower;
    int_result = sqlite3_create_function_v2(
            session->db,
            "lower",
            1,
            SQLITE_UTF8 | SQLITE_DETERMINISTIC,
            NULL,
            xFunc_lower,
            NULL,
            NULL,
            NULL);
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    /* Update the schema, if needed. */
    if (session->first_session_at_init_time) {
        if (version == 1) {
            // Sometimes the user_version wasn't set correctly.
            status = _verify_version(session, &version);
            if (status != PEP_STATUS_OK)
                FAIL(PEP_ILLEGAL_VALUE);
        }

        if (version > atoi(_DDL_USER_VERSION))
            // This is *explicitly* not allowed.
            FAIL(PEP_INIT_DB_DOWNGRADE_VIOLATION);
        if (version != 0) {
            // Version has been already set

            // Early mistake : version 0 shouldn't have existed.
            // Numbering should have started at 1 to detect newly created DB.
            // Version 0 DBs are not anymore compatible.
            status = _check_and_execute_upgrades(session, version);
            if (status != PEP_STATUS_OK)
                FAIL(PEP_ILLEGAL_VALUE);
        } else {
            // Version from DB was 0, it means this is initial setup.
            // DB has just been created, and all tables are empty.
            very_first = true;
        }

        if (version < atoi(_DDL_USER_VERSION)) {
            PEP_SQL_BEGIN_LOOP(int_result);
                int_result = sqlite3_exec(
                    session->db,
                    "pragma user_version = "_DDL_USER_VERSION";\n"
                    "insert or replace into version_info (id, version)"
                    "values (1, '" PEP_ENGINE_VERSION "');",
                    NULL,
                    NULL,
                    NULL);
            PEP_SQL_END_LOOP();
            if (int_result != SQLITE_OK)
                FAIL(PEP_UNKNOWN_DB_ERROR);
        }
    }
#if 0 && defined(_PEP_SQLITE_DEBUG)
    sqlite3_config(SQLITE_CONFIG_LOG, errorLogCallback, session);
    sqlite3_trace_v2(session->db,
                     SQLITE_TRACE_STMT | SQLITE_TRACE_ROW | SQLITE_TRACE_CLOSE,
                     sql_trace_callback,
                     session);
#endif

    /* Open the system database. */
    PEP_ASSERT(session->system_db == NULL);
    int_result = sqlite3_open_v2(SYSTEM_DB, &session->system_db,
                                 SQLITE_OPEN_READONLY
                                 | SQLITE_OPEN_FULLMUTEX
                                 | SQLITE_OPEN_SHAREDCACHE,
                                 NULL);
    if (int_result != SQLITE_OK)
        FAIL(PEP_INIT_CANNOT_OPEN_SYSTEM_DB);

    /* Perform some expensive SQL operations, for which we do not need to worry
       about concurrency. */
    if (session->first_session_at_init_time) {
        PEP_SQL_BEGIN_LOOP(int_result);
            int_result = sqlite3_exec(session->db,
  "PRAGMA integrity_check;\n"
  "PRAGMA optimize;\n"
  "VACUUM;\n"
  "PRAGMA journal_mode=WAL;\n" // specifically documented as persistent
  "",
                                      NULL, NULL, NULL);
        PEP_SQL_END_LOOP();
        if (int_result != SQLITE_OK) {
            LOG_NONOK("failed executing early first-session SQLite"
                      " statements: %s", pEp_sql_status_text(session));
            FAIL(PEP_UNKNOWN_DB_ERROR);
        }
    }

    /* Set database pragmas which affect only the current connection -- which
       means that the setting needs to be replicated for each new connection,
       be it the first or not. */
    PEP_SQL_BEGIN_LOOP(int_result);
        int_result = sqlite3_exec(
           session->db,
 "PRAGMA foreign_key=ON;\n"
 "PRAGMA synchronous=NORMAL;\n" // not persistent!
 "PRAGMA secure_delete = OFF;\n"
// "PRAGMA SQLITE_DEFAULT_WAL_AUTOCHECKPOINT = 1;\n" /* checkpoint very often. */
// "PRAGMA SQLITE_DEFAULT_WAL_AUTOCHECKPOINT = 100000;\n" /* checkpoint very rarely. */
// "PRAGMA SQLITE_DEFAULT_WAL_AUTOCHECKPOINT = 0;\n" /* do not checkpoint at all.  Probably not what we want. */
 "",
           NULL, NULL, NULL);
        if (int_result != SQLITE_OK) {
            LOG_NONOK("failed executing early SQLite statements: %s",
                      pEp_sql_status_text(session));
        }
    PEP_SQL_END_LOOP();
    if (int_result != SQLITE_OK)
        FAIL(PEP_UNKNOWN_DB_ERROR);
    /* positron: before 2023-05-04 there was a call to sqlite3_busy_timeout
       here, setting the busy wait time to 5 seconds.  I removed it.  We are now
       handling SQLITE_BUSY through the functionality in sql_reliabiliy.h and
       sql_reliabiliy.c . */
    sqlite3_busy_timeout(session->db, 0);
    //sqlite3_busy_timeout(session->db, 5000);

    if (session->first_session_at_init_time)
        LOG_TRACE("database schema initialised successfully from the FIRST session");
    else
        LOG_TRACE("database connection initialised successfully from a session"
                  " which is NOT the first");

    /* Now that the schema is ready we have to prepare statemets, for any
       connection. */
    status = _prepare_sql_stmts(session);
    if (status != PEP_STATUS_OK)
        FAIL(status);

 end:
    LOG_NONOK_STATUS_CRITICAL;
    if (status != PEP_STATUS_OK)
        LOG_CRITICAL("SQLite code is %s", pEp_sql_status_text(session));

    return status;
#undef FAIL
}

// This whole mess really does need to be generated somewhere.
static PEP_STATUS _prepare_sql_stmts(PEP_SESSION session) {
    PEP_REQUIRE(session);
    int int_result = SQLITE_OK;

#define PREPARE(db_field_name, session_field_name)                          \
    do {                                                                    \
        /* LOG_TRACE("preparing %s (%s)",                                   \
                  # session_field_name, # db_field_name); */                \
        int_result = pEp_sqlite3_prepare_v2_nonbusy_nonlocked(              \
                        session,                                            \
                        session->db_field_name,                             \
                        sql_ ## session_field_name,                         \
                        (int) strlen(sql_ ## session_field_name),           \
                        & session->session_field_name,                      \
                        NULL);                                              \
        if (int_result != SQLITE_OK) {                                      \
            LOG_CRITICAL("failed to initialise SQL statement: %s",          \
                         sql_ ## session_field_name );                      \
            LOG_CRITICAL("SQLite error: %s", pEp_sql_status_text(session)); \
            return PEP_UNKNOWN_DB_ERROR;                                    \
        }                                                                   \
    } while (false)

    /* Trustwords / system db. */
    PREPARE(system_db, trustword);
    PREPARE(system_db, languagelist);
    PREPARE(system_db, i18n_token);

    /* Everything else: management db. */
    PREPARE(db, begin_exclusive_transaction);
    PREPARE(db, commit_transaction);
    PREPARE(db, rollback_transaction);
    PREPARE(db, get_identity);
    PREPARE(db, get_identity_without_trust_check);
    PREPARE(db, get_identities_by_address);
    PREPARE(db, get_identities_by_userid);
    PREPARE(db, get_identities_by_main_key_id);
    PREPARE(db, set_default_identity_fpr);
    PREPARE(db, get_default_identity_fpr);
    PREPARE(db, get_user_default_key);
    PREPARE(db, get_all_keys_for_user);
    PREPARE(db, get_all_keys_for_identity);
    PREPARE(db, get_default_own_userid);
    PREPARE(db, get_userid_alias_default);
    PREPARE(db, add_userid_alias);
    PREPARE(db, add_userid_alias);
    PREPARE(db, replace_userid);
    PREPARE(db, delete_key);
    PREPARE(db, replace_main_user_fpr);
    PREPARE(db, replace_main_user_fpr_if_equal);
    PREPARE(db, get_main_user_fpr);
    PREPARE(db, refresh_userid_default_key);
    PREPARE(db, replace_identities_fpr);
    PREPARE(db, remove_fpr_as_identity_default);
    PREPARE(db, remove_fpr_as_user_default);
    PREPARE(db, set_person);
    PREPARE(db, update_person);
    PREPARE(db, delete_person);
    PREPARE(db, exists_person);
    PREPARE(db, set_as_pEp_user);
    PREPARE(db, is_pEp_user);
    PREPARE(db, add_into_social_graph);
    PREPARE(db, get_own_address_binding_from_contact);
    PREPARE(db, set_revoke_contact_as_notified);
    PREPARE(db, get_contacted_ids_from_revoke_fpr);
    PREPARE(db, was_id_for_revoke_contacted);
    PREPARE(db, has_id_contacted_address);
    PREPARE(db, get_last_contacted);
    PREPARE(db, set_pgp_keypair);
    PREPARE(db, set_pgp_keypair_flags);
    PREPARE(db, unset_pgp_keypair_flags);
    PREPARE(db, set_identity_entry);
    PREPARE(db, update_identity_entry);
    PREPARE(db, exists_identity_entry);
    PREPARE(db, force_set_identity_username);
    PREPARE(db, set_identity_flags);
    PREPARE(db, unset_identity_flags);
    PREPARE(db, set_ident_enc_format);
    PREPARE(db, set_protocol_version);
    PREPARE(db, upgrade_protocol_version_by_user_id);
    PREPARE(db, clear_trust_info);
    PREPARE(db, set_trust);
    PREPARE(db, update_trust);
    PREPARE(db, update_trust_to_pEp);
    PREPARE(db, exists_trust_entry);
    PREPARE(db, update_trust_for_fpr);
    PREPARE(db, get_trust);
    PREPARE(db, get_trust_by_userid);
    PREPARE(db, least_trust);
    PREPARE(db, update_key_sticky_bit_for_user);
    PREPARE(db, is_key_sticky_for_user);
    PREPARE(db, mark_compromised);

    // Own keys
    PREPARE(db, own_key_is_listed);
    PREPARE(db, is_own_address);
    PREPARE(db, own_identities_retrieve);
    PREPARE(db, own_keys_retrieve);
    // PREPARE(db, set_own_key);

    // Sequence
    PREPARE(db, sequence_value1);
    PREPARE(db, sequence_value2);

    // Revocation tracking
    PREPARE(db, set_revoked);
    PREPARE(db, get_revoked);
    PREPARE(db, get_replacement_fpr);
    PREPARE(db, add_mistrusted_key);
    PREPARE(db, delete_mistrusted_key);
    PREPARE(db, is_mistrusted_key);

    /* Groups */
    PREPARE(db, create_group);
    PREPARE(db, enable_group);
    PREPARE(db, disable_group);
    PREPARE(db, exists_group_entry);
    PREPARE(db, group_add_member);
    PREPARE(db, group_delete_member);
    PREPARE(db, set_group_member_status);
    PREPARE(db, group_join);
    PREPARE(db, leave_group);
    PREPARE(db, get_all_members);
    PREPARE(db, get_active_members);
    PREPARE(db, get_all_groups);
    PREPARE(db, get_active_groups);
    PREPARE(db, add_own_membership_entry);
    PREPARE(db, get_own_membership_status);
    PREPARE(db, retrieve_own_membership_info_for_group_and_ident);
    PREPARE(db, retrieve_own_membership_info_for_group);
    PREPARE(db, get_group_manager);
    PREPARE(db, is_invited_group_member);
    PREPARE(db, is_active_group_member);
    PREPARE(db, is_group_active);
    // PREPARE(db, group_invite_exists);

    // Completely obsolete, I believe.
    PREPARE(db, log);

    return PEP_STATUS_OK;
#undef PREPARE
}

static PEP_STATUS _finalize_sql_stmts(PEP_SESSION session) {
    PEP_REQUIRE(session);

    sqlite3_finalize(session->trustword);
    sqlite3_finalize(session->log);
    sqlite3_finalize(session->begin_exclusive_transaction);
    sqlite3_finalize(session->commit_transaction);
    sqlite3_finalize(session->rollback_transaction);
    sqlite3_finalize(session->get_identity);
    sqlite3_finalize(session->get_identity_without_trust_check);
    sqlite3_finalize(session->get_identities_by_address);
    sqlite3_finalize(session->get_identities_by_userid);
    sqlite3_finalize(session->get_identities_by_main_key_id);
    sqlite3_finalize(session->get_user_default_key);
    sqlite3_finalize(session->get_all_keys_for_user);
    sqlite3_finalize(session->get_all_keys_for_identity);
    sqlite3_finalize(session->get_default_own_userid);
    sqlite3_finalize(session->get_userid_alias_default);
    sqlite3_finalize(session->add_userid_alias);
    sqlite3_finalize(session->replace_identities_fpr);
    sqlite3_finalize(session->set_default_identity_fpr);
    sqlite3_finalize(session->get_default_identity_fpr);
    sqlite3_finalize(session->remove_fpr_as_identity_default);
    sqlite3_finalize(session->remove_fpr_as_user_default);
    sqlite3_finalize(session->set_person);
    sqlite3_finalize(session->delete_person);
    sqlite3_finalize(session->update_person);
    sqlite3_finalize(session->set_as_pEp_user);
    sqlite3_finalize(session->upgrade_protocol_version_by_user_id);
    sqlite3_finalize(session->is_pEp_user);
    sqlite3_finalize(session->exists_person);
    sqlite3_finalize(session->add_into_social_graph);
    sqlite3_finalize(session->get_own_address_binding_from_contact);
    sqlite3_finalize(session->set_revoke_contact_as_notified);
    sqlite3_finalize(session->get_contacted_ids_from_revoke_fpr);
    sqlite3_finalize(session->was_id_for_revoke_contacted);
    sqlite3_finalize(session->has_id_contacted_address);
    sqlite3_finalize(session->get_last_contacted);
    sqlite3_finalize(session->set_pgp_keypair);
    sqlite3_finalize(session->exists_identity_entry);
    sqlite3_finalize(session->set_identity_entry);
    sqlite3_finalize(session->update_identity_entry);
    sqlite3_finalize(session->force_set_identity_username);
    sqlite3_finalize(session->set_identity_flags);
    sqlite3_finalize(session->unset_identity_flags);
    sqlite3_finalize(session->set_ident_enc_format);
    sqlite3_finalize(session->set_protocol_version);
    sqlite3_finalize(session->exists_trust_entry);
    sqlite3_finalize(session->clear_trust_info);
    sqlite3_finalize(session->set_trust);
    sqlite3_finalize(session->update_trust);
    sqlite3_finalize(session->update_trust_to_pEp);
    sqlite3_finalize(session->update_trust_for_fpr);
    sqlite3_finalize(session->get_trust);
    sqlite3_finalize(session->get_trust_by_userid);
    sqlite3_finalize(session->least_trust);
    sqlite3_finalize(session->update_key_sticky_bit_for_user);
    sqlite3_finalize(session->is_key_sticky_for_user);
    sqlite3_finalize(session->mark_compromised);
    sqlite3_finalize(session->languagelist);
    sqlite3_finalize(session->i18n_token);
    sqlite3_finalize(session->replace_userid);
    sqlite3_finalize(session->delete_key);
    sqlite3_finalize(session->replace_main_user_fpr);
    sqlite3_finalize(session->replace_main_user_fpr_if_equal);
    sqlite3_finalize(session->get_main_user_fpr);
    sqlite3_finalize(session->refresh_userid_default_key);
    sqlite3_finalize(session->own_key_is_listed);
    sqlite3_finalize(session->is_own_address);
    sqlite3_finalize(session->own_identities_retrieve);
    sqlite3_finalize(session->own_keys_retrieve);
    //     sqlite3_finalize(session->set_own_key);
    sqlite3_finalize(session->sequence_value1);
    sqlite3_finalize(session->sequence_value2);
    sqlite3_finalize(session->set_revoked);
    sqlite3_finalize(session->get_revoked);
    sqlite3_finalize(session->get_replacement_fpr);
    sqlite3_finalize(session->add_mistrusted_key);
    sqlite3_finalize(session->delete_mistrusted_key);
    sqlite3_finalize(session->is_mistrusted_key);
    sqlite3_finalize(session->create_group);
    sqlite3_finalize(session->enable_group);
    sqlite3_finalize(session->disable_group);
    sqlite3_finalize(session->exists_group_entry);
    sqlite3_finalize(session->group_add_member);
    sqlite3_finalize(session->group_delete_member);
    sqlite3_finalize(session->set_group_member_status);
    sqlite3_finalize(session->group_join);
    sqlite3_finalize(session->leave_group);
    sqlite3_finalize(session->get_all_members);
    sqlite3_finalize(session->get_active_members);
    sqlite3_finalize(session->get_active_groups);
    sqlite3_finalize(session->get_all_groups);
    sqlite3_finalize(session->add_own_membership_entry);
    sqlite3_finalize(session->get_own_membership_status);
    sqlite3_finalize(session->retrieve_own_membership_info_for_group_and_ident);
    sqlite3_finalize(session->retrieve_own_membership_info_for_group);
    sqlite3_finalize(session->get_group_manager);
    sqlite3_finalize(session->is_invited_group_member);
    sqlite3_finalize(session->is_active_group_member);
    sqlite3_finalize(session->is_group_active);
    sqlite3_finalize(session->set_pgp_keypair_flags);
    sqlite3_finalize(session->unset_pgp_keypair_flags);
//        sqlite3_finalize(session->group_invite_exists);
    return PEP_STATUS_OK;
}

PEP_STATUS pEp_sql_finalize(PEP_SESSION session,
                            bool is_this_the_last_session)
{
    PEP_REQUIRE(session);
    PEP_STATUS status = PEP_STATUS_OK;

    /* Finalize the statements. */
    status = _finalize_sql_stmts(session);
    LOG_NONOK_STATUS_CRITICAL;  /* It is probably useless to abort here. */

    /* Now we can close the database. */
    if (session->db) {
        if (is_this_the_last_session) {
            int int_result = SQLITE_OK;
            PEP_SQL_BEGIN_LOOP(int_result);
                int_result = sqlite3_exec(session->db,
                                          "PRAGMA optimize;\n",
                                          NULL, NULL, NULL);
            PEP_SQL_END_LOOP();
        }
        sqlite3_close_v2(session->db);
    }
    if (session->system_db)
        sqlite3_close_v2(session->system_db);

    return status;
}


/* Debugging
 * ***************************************************************** */

/* Return the name of an SQLite3 error code (be it extended or not) as a pointer
   to statically-allocated memory. */
static const char *pEp_sqlite3_errname(int sqlite_error_code)
{
#define HANDLE(code)              \
        case code: return #code;
    switch (sqlite_error_code) {
        /* Non-extended result codes. */
        HANDLE(SQLITE_OK);
        HANDLE(SQLITE_ERROR);
        HANDLE(SQLITE_INTERNAL);
        HANDLE(SQLITE_PERM);
        HANDLE(SQLITE_ABORT);
        HANDLE(SQLITE_BUSY);
        HANDLE(SQLITE_LOCKED);
        HANDLE(SQLITE_NOMEM);
        HANDLE(SQLITE_READONLY);
        HANDLE(SQLITE_INTERRUPT);
        HANDLE(SQLITE_IOERR);
        HANDLE(SQLITE_CORRUPT);
        HANDLE(SQLITE_NOTFOUND);
        HANDLE(SQLITE_FULL);
        HANDLE(SQLITE_CANTOPEN);
        HANDLE(SQLITE_PROTOCOL);
        HANDLE(SQLITE_EMPTY);
        HANDLE(SQLITE_SCHEMA);
        HANDLE(SQLITE_TOOBIG);
        HANDLE(SQLITE_CONSTRAINT);
        HANDLE(SQLITE_MISMATCH);
        HANDLE(SQLITE_MISUSE);
        HANDLE(SQLITE_NOLFS);
        HANDLE(SQLITE_AUTH);
        HANDLE(SQLITE_FORMAT);
        HANDLE(SQLITE_RANGE);
        HANDLE(SQLITE_NOTADB);
        HANDLE(SQLITE_NOTICE);
        HANDLE(SQLITE_WARNING);
        HANDLE(SQLITE_ROW);
        HANDLE(SQLITE_DONE);

        /* Extended result codes. */
        HANDLE(SQLITE_ERROR_MISSING_COLLSEQ);
        HANDLE(SQLITE_ERROR_RETRY);
        HANDLE(SQLITE_ERROR_SNAPSHOT);
        HANDLE(SQLITE_IOERR_READ);
        HANDLE(SQLITE_IOERR_SHORT_READ);
        HANDLE(SQLITE_IOERR_WRITE);
        HANDLE(SQLITE_IOERR_FSYNC);
        HANDLE(SQLITE_IOERR_DIR_FSYNC);
        HANDLE(SQLITE_IOERR_TRUNCATE);
        HANDLE(SQLITE_IOERR_FSTAT);
        HANDLE(SQLITE_IOERR_UNLOCK);
        HANDLE(SQLITE_IOERR_RDLOCK);
        HANDLE(SQLITE_IOERR_DELETE);
        HANDLE(SQLITE_IOERR_BLOCKED);
        HANDLE(SQLITE_IOERR_NOMEM);
        HANDLE(SQLITE_IOERR_ACCESS);
        HANDLE(SQLITE_IOERR_CHECKRESERVEDLOCK);
        HANDLE(SQLITE_IOERR_LOCK);
        HANDLE(SQLITE_IOERR_CLOSE);
        HANDLE(SQLITE_IOERR_DIR_CLOSE);
        HANDLE(SQLITE_IOERR_SHMOPEN);
        HANDLE(SQLITE_IOERR_SHMSIZE);
        HANDLE(SQLITE_IOERR_SHMLOCK);
        HANDLE(SQLITE_IOERR_SHMMAP);
        HANDLE(SQLITE_IOERR_SEEK);
        HANDLE(SQLITE_IOERR_DELETE_NOENT);
        HANDLE(SQLITE_IOERR_MMAP);
        HANDLE(SQLITE_IOERR_GETTEMPPATH);
        HANDLE(SQLITE_IOERR_CONVPATH);
        HANDLE(SQLITE_IOERR_VNODE);
        HANDLE(SQLITE_IOERR_AUTH);
        HANDLE(SQLITE_IOERR_BEGIN_ATOMIC);
        HANDLE(SQLITE_IOERR_COMMIT_ATOMIC);
        HANDLE(SQLITE_IOERR_ROLLBACK_ATOMIC);
        HANDLE(SQLITE_IOERR_DATA);
        HANDLE(SQLITE_IOERR_CORRUPTFS);
        HANDLE(SQLITE_LOCKED_SHAREDCACHE);
        HANDLE(SQLITE_LOCKED_VTAB);
        HANDLE(SQLITE_BUSY_RECOVERY);
        HANDLE(SQLITE_BUSY_SNAPSHOT);
        HANDLE(SQLITE_BUSY_TIMEOUT);
        HANDLE(SQLITE_CANTOPEN_NOTEMPDIR);
        HANDLE(SQLITE_CANTOPEN_ISDIR);
        HANDLE(SQLITE_CANTOPEN_FULLPATH);
        HANDLE(SQLITE_CANTOPEN_CONVPATH);
        HANDLE(SQLITE_CANTOPEN_DIRTYWAL);
        HANDLE(SQLITE_CANTOPEN_SYMLINK);
        HANDLE(SQLITE_CORRUPT_VTAB);
        HANDLE(SQLITE_CORRUPT_SEQUENCE);
        HANDLE(SQLITE_CORRUPT_INDEX);
        HANDLE(SQLITE_READONLY_RECOVERY);
        HANDLE(SQLITE_READONLY_CANTLOCK);
        HANDLE(SQLITE_READONLY_ROLLBACK);
        HANDLE(SQLITE_READONLY_DBMOVED);
        HANDLE(SQLITE_READONLY_CANTINIT);
        HANDLE(SQLITE_READONLY_DIRECTORY);
        HANDLE(SQLITE_ABORT_ROLLBACK);
        HANDLE(SQLITE_CONSTRAINT_CHECK);
        HANDLE(SQLITE_CONSTRAINT_COMMITHOOK);
        HANDLE(SQLITE_CONSTRAINT_FOREIGNKEY);
        HANDLE(SQLITE_CONSTRAINT_FUNCTION);
        HANDLE(SQLITE_CONSTRAINT_NOTNULL);
        HANDLE(SQLITE_CONSTRAINT_PRIMARYKEY);
        HANDLE(SQLITE_CONSTRAINT_TRIGGER);
        HANDLE(SQLITE_CONSTRAINT_UNIQUE);
        HANDLE(SQLITE_CONSTRAINT_VTAB);
        HANDLE(SQLITE_CONSTRAINT_ROWID);
        HANDLE(SQLITE_CONSTRAINT_PINNED);
        HANDLE(SQLITE_CONSTRAINT_DATATYPE);
        HANDLE(SQLITE_NOTICE_RECOVER_WAL);
        HANDLE(SQLITE_NOTICE_RECOVER_ROLLBACK);
        // HANDLE(SQLITE_NOTICE_RBU);  // only in very recent versions, I suppose.
        HANDLE(SQLITE_WARNING_AUTOINDEX);
        HANDLE(SQLITE_AUTH_USER);
        HANDLE(SQLITE_OK_LOAD_PERMANENTLY);
        HANDLE(SQLITE_OK_SYMLINK);

        /* Anything else. */
        default: return "<unknown or invalid sqlite error code>";
    }
#undef HANDLE
}

/* The functions defined from now in this compilation unit on are only used
   internally and should not pollute the log with frequent and uninteresting
   entries every time one of them is called.  */
#define PEP_NO_LOG_FUNCTION_ENTRY  1

const char *pEp_sql_status_text_for_database(PEP_SESSION session, sqlite3 *db)
{
    PEP_REQUIRE_ORELSE_RETURN(session && db, "<wrong arguments>");

    /* First, delete any old data. */
    if (session->sql_status_text != NULL) {
        free(session->sql_status_text);
        session->sql_status_text = NULL;
    }

    /* Obtain the error code. */
    int sqlite_error_code = sqlite3_extended_errcode(db);

    /* Compute the required length.  The longest SQLite status name is currently
       SQLITE_NOTICE_RECOVER_ROLLBACK. */
    const char *status_name = pEp_sqlite3_errname(sqlite_error_code);

    size_t number_length = 10; /* Safe bound: SQLite statuses are 32-bit */
    size_t string_size = (number_length
                          + strlen(status_name)
                          + 3 /* '(' ')' ' '*/
                          + /* '\0' */ 1);

    /* Compose the string and return it.  In case of allocation failure, return
       a statically-allocated string which is still correct for the user, who is
       not supposed to free any string returned from here.  However it is
       important that we do not point to statically allocated strings from
       session->sql_status_text. */
    session->sql_status_text = malloc(string_size);
    if (session->sql_status_text == NULL)
        return "pEp_sql_status_text: could not allocate. ";
    sprintf(session->sql_status_text, "(%li) %s",
            (long) sqlite_error_code, status_name);

    return session->sql_status_text;
}

const char *pEp_sql_status_text(PEP_SESSION session)
{
    PEP_REQUIRE_ORELSE_RETURN(session, "<wrong argument>");
    return pEp_sql_status_text_for_database(session, session->db);
}
