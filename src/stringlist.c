// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "stringlist.h"


DYNAMIC_API stringlist_t *new_stringlist(const char *value)
{
    stringlist_t *result = calloc(1, sizeof(stringlist_t));
    assert(result);

    if (result && value) {
        result->value = strdup(value);
        assert(result->value);
        if (result->value == 0) {
            free(result);
            return NULL;
        }
    }

    return result;
}

DYNAMIC_API stringlist_t *stringlist_dup(const stringlist_t *src)
{
    assert(src);
    if (src == NULL)
        return NULL;

    stringlist_t *dst = new_stringlist(src->value);
    if (dst == NULL)
        return NULL;

    stringlist_t* src_curr = src->next;
    stringlist_t** dst_curr_ptr = &dst->next;
    
    while (src_curr) {
        *dst_curr_ptr = new_stringlist(src_curr->value);
        if (*dst_curr_ptr == NULL) {
            free_stringlist(dst);
            return NULL;
        }
        src_curr = src_curr->next;
        dst_curr_ptr = &((*dst_curr_ptr)->next);
    }

    return dst;
}

static bool _stringlist_add_first(
        stringlist_t *stringlist,
        stringlist_t **result,
        const char *value
    )
{  
    // empty list (no nodes)
    if (stringlist == NULL) {
        *result = new_stringlist(value);
        return true;
    }

    // empty list (one node, no value)
    if (stringlist->value == NULL) {
        if (stringlist->next) {
            *result = NULL; // invalid list
            return true;
        } 
            
        stringlist->value = strdup(value);
        assert(stringlist->value);
        
        if (stringlist->value == NULL) {
            *result = NULL;
            return true;
        }
        
        *result = stringlist;
        return true;
    }
    return false;
}

DYNAMIC_API stringlist_t *stringlist_add(
        stringlist_t *stringlist,
        const char *value
    )
{  
    assert(value);
    if (value == NULL)
        return NULL;

    stringlist_t *result = NULL;
    if(_stringlist_add_first(stringlist, &result, value))
        return result;
    
    stringlist_t* list_curr = stringlist;

    while (list_curr->next)
        list_curr = list_curr->next;
     
    list_curr->next = new_stringlist(value);

    assert(list_curr->next);
    if (list_curr->next == NULL)
        return NULL;

    return list_curr->next;
}

stringlist_t* stringlist_search(stringlist_t* head, const char* value) {
    if (!head || !value || !head->value)
        return NULL;
    stringlist_t* retval = head;
    for (; retval ; retval = retval->next) {
        if (strcmp(retval->value, value) == 0))
            break;
    }
    return retval;
}

DYNAMIC_API stringlist_t *stringlist_add_unique(
        stringlist_t *stringlist,
        const char *value
    )
{  
    assert(value);
    if (value == NULL)
        return NULL;

    stringlist_t *result = NULL;
    if(_stringlist_add_first(stringlist, &result, value))
        return result;
    
    stringlist_t* list_curr = stringlist;

    bool found = false;
    while (list_curr->next) {
        if(strcmp(list_curr->value,value)==0)
            found = true;
        list_curr = list_curr->next;
    }
     
    if (!found) {
        list_curr->next = new_stringlist(value);

        assert(list_curr->next);
        if (list_curr->next == NULL)
            return NULL;

        return list_curr->next;
    } else {
        return list_curr;
    }
}


DYNAMIC_API stringlist_t *stringlist_append(
        stringlist_t *stringlist,
        stringlist_t *second
    )
{
    assert(stringlist);
    if (stringlist == NULL)
        return NULL;

    // Second list is empty
    if (second == NULL || second->value == NULL)
        return stringlist;

    stringlist_t *_s = stringlist;
    stringlist_t *_s2;
    for (_s2 = second; _s2 != NULL; _s2 = _s2->next) {
        _s = stringlist_add(_s, _s2->value);
        if (_s == NULL)
            return NULL;
    }
    return _s;
}

DYNAMIC_API int stringlist_length(const stringlist_t *stringlist)
{
    int len = 0;

    const stringlist_t *_sl;
    for (_sl = stringlist; _sl && _sl->value; _sl = _sl->next)
        len++;

    return len;
}

DYNAMIC_API stringlist_t *stringlist_delete(
        stringlist_t *stringlist,
        const char *value
    )
{
    assert(stringlist);
    assert(value);

    if (stringlist->value == NULL) {
        free_stringlist(stringlist);
        return NULL;
    }

    if (value == NULL)
        return stringlist;

    stringlist_t *_sl;
    stringlist_t *last = NULL;
    for (_sl = stringlist; _sl && _sl->value; _sl = _sl->next) {
        if (strcmp(_sl->value, value) == 0) {
            if (last == NULL)
                stringlist = stringlist->next;
            else
                last->next = _sl->next;
            _sl->next = NULL;
            free_stringlist(_sl);
            break;
        }
        last = _sl;
    }
    return stringlist;
}

DYNAMIC_API void free_stringlist(stringlist_t *stringlist)
{
    stringlist_t *curr = stringlist;
    
    while (curr) {
        stringlist_t *next = curr->next;
        free(curr->value);
        curr->value = NULL;
        free(curr);
        curr = next;
    }
}
