/**
 * @file    stringpair.h
 * @brief   stringpair struct and list struct builders, accessors, manipulators
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef STRINGPAIR_H
#define STRINGPAIR_H

#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  @struct    stringpair_t
 *  
 *  @brief    TODO
 *  
 */
typedef struct _stringpair_t {
    char * key;   // may point to "" but must not be NULL!
    char * value; // may point to "" but must not be NULL!
} stringpair_t;


/**
 *  <!--       new_stringpair()       -->
 *  
 *  @brief Allocate new stringpair_t
 *  
 *  @param[in]   key      utf-8 string used as key, should not be NULL
 *  @param[in]   value    utf-8 string containing the value, should not be NULL
 *  
 *  @retval pointer to stringpair_t or NULL on failure
 *  
 *  @warning key and value are copied and remain in the ownership of the caller
 *  
 */

DYNAMIC_API stringpair_t * new_stringpair(const char *key, const char *value);


/**
 *  <!--       free_stringpair()       -->
 *  
 *  @brief Free memory allocated by stringpair_t
 *  
 *  @param[in]   pair    pointer to stringpair_t to free
 *  
 *  
 */

DYNAMIC_API void free_stringpair(stringpair_t * pair);


/**
 *  <!--       stringpair_dup()       -->
 *  
 *  @brief Duplicate stringpair_t (deep copy)
 *  
 *  @param[in]   src    pointer to stringpair_t to duplicate
 *  
 *  @retval pointer to copy of src or NULL on failure
 *  
 *  
 */

DYNAMIC_API stringpair_t * stringpair_dup(const stringpair_t *src);


/**
 *  @struct    stringpair_list_t
 *  
 *  @brief    TODO
 *  
 */
typedef struct _stringpair_list_t {
    stringpair_t *value;
    struct _stringpair_list_t *next;
} stringpair_list_t;


/**
 *  <!--       new_stringpair_list()       -->
 *  
 *  @brief Allocate a new stringpair_list
 *  
 *  @param[in]   value    initial value
 *  
 *  @retval pointer to stringpair_list_t object or NULL if out of memory
 *  
 *  @warning the ownership of the value goes to the stringpair_list
 *           next pointer is NULL
 *  
 */

DYNAMIC_API stringpair_list_t *new_stringpair_list(stringpair_t *value);


/**
 *  <!--       stringpair_list_dup()       -->
 *  
 *  @brief Duplicate a stringpair_list (deep copy)
 *  
 *  @param[in]   src    stringpair_list to copy
 *  
 *  @retval pointer to stringpair_list_t object or NULL if out of memory
 *  @retval stringpair value copies created by this function belong to the returned list
 *  
 *  
 */

DYNAMIC_API stringpair_list_t *stringpair_list_dup(
        const stringpair_list_t *src
    );


/**
 *  <!--       stringpair_list_add()       -->
 *  
 *  @brief Add key to stringpair_list
 *  
 *  @param[in]   stringpair_list    stringpair_list struct or NULL to create a new
 *                                    one
 *  @param[in]   value              stringpair to add
 *  
 *  @retval pointer to last element in stringpair_list or NULL if out of memory
 *  
 *  @warning the ownership of the value goes to the stringpair_list if add is successful
 *  
 */

DYNAMIC_API stringpair_list_t *stringpair_list_add(
        stringpair_list_t *stringpair_list,
        stringpair_t *value
    );


/**
 *  <!--       stringpair_list_append()       -->
 *  
 *  @brief Append stringpair_list to stringpair_list
 *  
 *  @param[in]   stringpair_list    stringpair_list struct to append to
 *  @param[in]   second             stringpair_list struct to append
 *  
 *  @retval pointer to last element in stringpair_list or NULL if out of memory
 *  @retval or stringpair_list is NULL
 *  
 *  @warning all values are being copied before being added to the list
 *           the original values are still being owned by the caller
 *  
 */

DYNAMIC_API stringpair_list_t *stringpair_list_append(
        stringpair_list_t *stringpair_list,
        stringpair_list_t *second
    );


/**
 *  <!--       stringpair_list_length()       -->
 *  
 *  @brief Get length of stringpair_list
 *  
 *  @param[in]   stringpair_list    stringpair_list struct to determine length of
 *  
 *  @retval length of stringpair_list in number of elements
 *  
 *  
 */

DYNAMIC_API int stringpair_list_length(
        const stringpair_list_t *stringpair_list
    );


/**
 *  <!--       free_stringpair_list()       -->
 *  
 *  @brief Free memory occupied by stringpair_list
 *  
 *  @param[in]   stringpair_list    stringpair_list to free
 *  
 *  
 */

DYNAMIC_API void free_stringpair_list(stringpair_list_t *stringpair_list);


/**
 *  <!--       stringpair_list_find()       -->
 *  
 *  @brief Find element in list using key
 *  
 *  @param[in]   stringpair_list    list to search
 *  @param[in]   key                key to search for
 *  
 *  @retval node with result if found or NULL if not
 *  
 *  
 */

DYNAMIC_API stringpair_list_t *stringpair_list_find(
        stringpair_list_t *stringpair_list,
        const char *key
    );

/**
 *  <!--       stringpair_list_find_case_insensitive()       -->
 *  
 *  @brief Identical to stringpair_list_find except that the key comparison
 *         is performed case-insensitively; of course there is no restriction
 *         on values.
 *  
 */
DYNAMIC_API stringpair_list_t *stringpair_list_find_case_insensitive(
        stringpair_list_t *stringpair_list,
        const char *key
    );

// ONLY DELETES ONE.
/**
 *  <!--       stringpair_list_delete_by_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  sp_list     stringpair_list_t*
 *  @param[in]  key         const char*
 *  
 */
DYNAMIC_API stringpair_list_t *stringpair_list_delete_by_key(
        stringpair_list_t *sp_list,
        const char *key
    );

/**
 *  <!--       stringpair_list_delete_by_key_case_insensitive()       -->
 *
 *  @brief Identical to stringpair_list_delete_by_key except that the key
 *         comparison is performed case-insensitively; of course there is no
 *         restriction on values.
 *
 */
DYNAMIC_API stringpair_list_t *stringpair_list_delete_by_key_case_insensitive(
        stringpair_list_t *sp_list,
        const char *key
    );


#ifdef __cplusplus
}
#endif

#endif
