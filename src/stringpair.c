/** 
 * @file stringpair.c
 * @brief File description for doxygen missing. FIXME   
 *
 * @license This file is under GNU General Public License 3.0
 * see LICENSE.txt
 */

/* In this compilation unit, like in others, functions do not take a session as
   a paramter; this prevents me from using the new debugging and logging
   functionalities.  I wonder if we should systematically add a session paramter
   to our functions, even when not needed, just for this.  --positron,
   2022-10 */

#include "pEp_internal.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "stringpair.h"

/* Exactly like strcasecmp, but guaranteed to be defined as a function and not
   only as a macro.  Unfortunately we need this for windows. */
static int strcasecmp_as_a_function(const char *a, const char *b)
{
    return strcasecmp(a, b);
}


DYNAMIC_API stringpair_t * new_stringpair(const char *key, const char *value)
{
    stringpair_t *pair = NULL;

    // key and value should not be NULL, that's bad style (while legal)

    assert(key);
    assert(value);

    pair = calloc(1, sizeof(stringpair_t));
    assert(pair);
    if (pair == NULL)
        goto enomem;

    pair->key = key ? strdup(key) : strdup("");
    assert(pair->key);
    if (pair->key == NULL)
        goto enomem;

    pair->value = value ? strdup(value) : strdup("");
    assert(pair->value);
    if (pair->value == NULL)
        goto enomem;

    return pair;

enomem:
    free_stringpair(pair);
    return NULL;
}

DYNAMIC_API void free_stringpair(stringpair_t * pair)
{
    if (pair) {
        free(pair->key);
        free(pair->value);
        free(pair);
    }
}

DYNAMIC_API stringpair_t * stringpair_dup(const stringpair_t *src)
{
    assert(src);
    if (src == NULL)
        return NULL;
    
    return new_stringpair(src->key, src->value);
}

DYNAMIC_API stringpair_list_t *new_stringpair_list(stringpair_t *value)
{
    stringpair_list_t *result = calloc(1, sizeof(stringpair_list_t));
    assert(result);

    if (result && value)
        result->value = value;
    
    return result;
}

DYNAMIC_API stringpair_list_t *stringpair_list_dup(
        const stringpair_list_t *src
    )
{
    assert(src);
    if (src == NULL)
        return NULL;

    stringpair_t* copy_pair = stringpair_dup(src->value);
    if (!copy_pair)
        return NULL;
    
    stringpair_list_t *dst = new_stringpair_list(copy_pair);
    if (dst == NULL)
        return NULL;

    stringpair_list_t* src_curr = src->next;
    stringpair_list_t** dst_curr_ptr = &dst->next;

    while (src_curr) {
        copy_pair = stringpair_dup(src_curr->value);
        if (copy_pair == NULL) {
            free_stringpair_list(dst);
            return NULL;
        }
        *dst_curr_ptr = new_stringpair_list(copy_pair);
        if (*dst_curr_ptr == NULL) {
            free_stringpair(copy_pair);
            free_stringpair_list(dst);
            return NULL;
        }
        src_curr = src_curr->next;
        dst_curr_ptr = &((*dst_curr_ptr)->next);
    }

    return dst;
    
}

DYNAMIC_API stringpair_list_t *stringpair_list_add(
        stringpair_list_t *stringpair_list,
        stringpair_t *value
    )
{
    assert(value);

    if (!value)
        return NULL;

    // empty list (no nodes)
    if (stringpair_list == NULL)
        return new_stringpair_list(value);

    // empty list (one node, no value)
    if (stringpair_list->value == NULL) {
        if (stringpair_list->next)
            return NULL; // invalid list
            
        stringpair_list->value = value;
        assert(stringpair_list->value);
        
        if (stringpair_list->value == NULL)
            return NULL;
        
        return stringpair_list;
    }
    
    stringpair_list_t* list_curr = stringpair_list;
    
    while (list_curr->next)
        list_curr = list_curr->next;
     
    list_curr->next = new_stringpair_list(value);

    assert(list_curr->next);
    if (list_curr->next == NULL)
        return NULL;

    return list_curr->next;
    
}

DYNAMIC_API stringpair_list_t *stringpair_list_append(
        stringpair_list_t *stringpair_list,
        stringpair_list_t *second
    )
{
    assert(stringpair_list);
    if (stringpair_list == NULL)
        return NULL;

    // second list is empty
    if (second == NULL || second->value == NULL)
        return stringpair_list;

    stringpair_list_t *_s = stringpair_list;
    for (stringpair_list_t *_s2 = second; _s2 != NULL; _s2 = _s2->next) {
        stringpair_t *_sp = stringpair_dup(_s2->value);
        if (_sp == NULL)
            return NULL;
        _s = stringpair_list_add(_s, _sp);
        if (_s == NULL){
            free_stringpair(_sp);
            return NULL;
        }
    }
    return _s;
}

DYNAMIC_API int stringpair_list_length(
        const stringpair_list_t *stringpair_list
    )
{
    if (!stringpair_list)
        return 0;

    int len = 0;

    for (const stringpair_list_t *_sl = stringpair_list; _sl && _sl->value; _sl = _sl->next)
        len++;

    return len;
}

DYNAMIC_API void free_stringpair_list(stringpair_list_t *stringpair_list)
{
    if (stringpair_list) {
        free_stringpair_list(stringpair_list->next);
        free_stringpair(stringpair_list->value);
        free(stringpair_list);
    }
}

// ONLY DELETES ONE.
static stringpair_list_t *stringpair_list_delete_by_key_possibly_case_sensitive(
        stringpair_list_t *sp_list,
        const char *key,
        bool case_sensitive
    )
{
    assert(key);

    if (!key || !sp_list)
        return NULL;

    if (sp_list->value == NULL) {
        free_stringpair_list(sp_list);
        return NULL;
    }

    if (key == NULL)
        return sp_list;

    int (*comparison_function)(const char *, const char *);
    if (case_sensitive)
        comparison_function = strcoll;
    else
        comparison_function = strcasecmp_as_a_function;

    stringpair_list_t *_sl;
    stringpair_list_t *last = NULL;
    for (_sl = sp_list; _sl && _sl->value && _sl->value->key; _sl = _sl->next) {
        if (comparison_function(_sl->value->key, key) == 0) {
            if (last == NULL)
                sp_list = sp_list->next;
            else
                last->next = _sl->next;
            _sl->next = NULL;
            free_stringpair_list(_sl);
            break;
        }
        last = _sl;
    }
    return sp_list;
}

DYNAMIC_API stringpair_list_t *stringpair_list_delete_by_key(
        stringpair_list_t *sp_list,
        const char *key
    )
{
    return stringpair_list_delete_by_key_possibly_case_sensitive(sp_list, key,
                                                                 true);
}

DYNAMIC_API stringpair_list_t *stringpair_list_delete_by_key_case_insensitive(
        stringpair_list_t *sp_list,
        const char *key
    )
{
    return stringpair_list_delete_by_key_possibly_case_sensitive(sp_list, key,
                                                                 false);
}

static stringpair_list_t *stringpair_list_find_possibly_case_sensitive(
        stringpair_list_t *stringpair_list,
        const char *key,
        bool case_sensitive
    )
{
    assert(key);

    if (!key || !stringpair_list || !stringpair_list->value)
        return NULL;

    int (*comparison_function)(const char *, const char *);
    if (case_sensitive)
        comparison_function = strcoll;
    else
        comparison_function = strcasecmp_as_a_function;

    for (stringpair_list_t *_l = stringpair_list; _l; _l = _l->next) {
        if (comparison_function(key, _l->value->key) == 0)
            return _l;
    }

    return NULL;
}

DYNAMIC_API stringpair_list_t *stringpair_list_find(
        stringpair_list_t *stringpair_list,
        const char *key
    )
{
    return stringpair_list_find_possibly_case_sensitive(stringpair_list, key,
                                                        true);
}

DYNAMIC_API stringpair_list_t *stringpair_list_find_case_insensitive(
        stringpair_list_t *stringpair_list,
        const char *key
    )
{
    return stringpair_list_find_possibly_case_sensitive(stringpair_list, key,
                                                        false);
}
