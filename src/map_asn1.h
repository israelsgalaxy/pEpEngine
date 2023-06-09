/**
 * @file    map_asn1.h
 * @brief   map asn1 to pEp structs and back
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef MAP_ASN1_H
#define MAP_ASN1_H

#include "message.h"
#include "ASN1Message.h"
#include "Identity.h"
#include "IdentityList.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file map_asn1.h
 * For compatibility reasons we have PIdentity as a distinct struct from
   Identity.  The difference is that PIdentity has some optional fields, notably
   fpr.

   Some functionality is replicated for each struct kind. */

/**
 *  <!--       PIdentity_from_Struct()       -->
 *  
 *  @brief Convert pEp_identity into ASN.1 PIdentity_t
 *  
 *  @param[in]     ident           pEp_identity to convert
 *  @param[in,out] result          PIdentity_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PIdentity_t *PIdentity_from_Struct(
        const pEp_identity *ident,
        PIdentity_t *result
    );


/**
 *  <!--       PIdentity_to_Struct()       -->
 *  
 *  @brief Convert ASN.1 PIdentity_t into pEp_identity
 *  
 *  @param[in]     ident          PIdentity_t to convert
 *  @param[in,out] result         pEp_identity to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

pEp_identity *PIdentity_to_Struct(PIdentity_t *ident, pEp_identity *result);


/**
 *  <!--       PIdentityList_from_identity_list()       -->
 *  
 *  @brief Convert identity_list_t into ASN.1 PIdentityList_t
 *  
 *  @param[in]    list           identity_list to convert
 *  @param[inout] result         PIdentityList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PIdentityList_t *PIdentityList_from_identity_list(
        const identity_list *list,
        PIdentityList_t *result
    );

/**
 *  <!--       PIdentityList_to_identity_list()       -->
 *  
 *  @brief Convert ASN.1 PIdentityList_t to identity_list_t
 *  
 *  @param[in]     list        ASN.1 PIdentityList_t to convert
 *  @param[in,out] result      identity_list_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

identity_list *PIdentityList_to_identity_list(PIdentityList_t *list, identity_list *result);


/**
 *  <!--       Identity_from_Struct()       -->
 *  
 *  @brief Convert pEp_identity into ASN.1 Identity_t
 *  
 *  @param[in]     ident       pEp_identity to convert
 *  @param[in,out] result      Identity_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

Identity_t *Identity_from_Struct(
        const pEp_identity *ident,
        Identity_t *result
    );


/**
 *  <!--       Identity_to_Struct()       -->
 *  
 *  @brief Convert ASN.1 Identity_t into pEp_identity
 *  
 *  @param[in]     ident       Identity_t to convert
 *  @param[in,out] result      pEp_identity to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

pEp_identity *Identity_to_Struct(Identity_t *ident, pEp_identity *result);


/**
 *  <!--       IdentityList_from_identity_list()       -->
 *  
 *  @brief Convert identity_list_t into ASN.1 IdentityList_t
 *  
 *  @param[in]    list        identity_list to convert
 *  @param[in,out] result      IdentityList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

IdentityList_t *IdentityList_from_identity_list(
        const identity_list *list,
        IdentityList_t *result
    );

/**
 *  <!--       IdentityList_to_identity_list()       -->
 *  
 *  @brief Convert ASN.1 IdentityList_t to identity_list_t
 *  
 *  @param[in]     list        ASN.1 IdentityList_t to convert
 *  @param[in,out] result      identity_list_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

identity_list *IdentityList_to_identity_list(IdentityList_t *list, identity_list *result);


/**
 *  <!--       PStringPair_from_Struct()       -->
 *  
 *  @brief Convert stringpair_t into ASN.1 PStringPair_t
 *  
 *  @param[in]     value       stringpair_t to convert
 *  @param[in,out] result      PStringPair_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PStringPair_t *PStringPair_from_Struct(
        const stringpair_t *value,
        PStringPair_t *result
    );


/**
 *  <!--       PStringPair_to_Struct()       -->
 *  
 *  @brief Convert ASN.1 PStringPair_t into stringpair_t
 *  
 *  @param[in] value          PStringPair_t to convert
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning a new struct is allocated, the ownership goes to the caller
 *  
 */

stringpair_t *PStringPair_to_Struct(PStringPair_t *value);


/**
 *  <!--       PStringPairList_from_stringpair_list()       -->
 *  
 *  @brief Convert stringpair_list_t into ASN.1 PStringPairList_t
 *  
 *  @param[in]    list        stringpair_list to convert
 *  @param[in,out] result     PStringPairList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PStringPairList_t *PStringPairList_from_stringpair_list(
        const stringpair_list_t *list,
        PStringPairList_t *result
    );

/**
 *  <!--       PStringPairList_to_stringpair_list()       -->
 *  
 *  @brief Convert ASN.1 PStringPairList_t to stringpair_list_t
 *  
 *  @param[in]    list          ASN.1 PStringPairList_t to convert
 *  @param[in,out] result       stringpair_list_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

stringpair_list_t *PStringPairList_to_stringpair_list(
        PStringPairList_t *list,
        stringpair_list_t *result
    );


/**
 *  <!--       PStringList_from_stringlist()       -->
 *  
 *  @brief Convert stringlist_t into ASN.1 PStringList_t
 *  
 *  @param[in]     list          stringlist to convert
 *  @param[in,out] result        PStringList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PStringList_t *PStringList_from_stringlist(
        const stringlist_t *list,
        PStringList_t *result
    );

/**
 *  <!--       PStringList_to_stringlist()       -->
 *  
 *  @brief Convert ASN.1 PStringList_t to stringlist_t
 *  
 *  @param[in] list           ASN.1 PStringList_t to convert
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning a new struct is allocated, the ownership goes to the caller
 *  
 */

stringlist_t *PStringList_to_stringlist(PStringList_t *list);


/**
 *  <!--       PBlobList_from_bloblist()       -->
 *  
 *  @brief Convert bloblist_t into ASN.1 PBlobList_t
 *  
 *  @param[in]    list           bloblist to convert
 *  @param[in,out] result        PBlobList_t to update or NULL to alloc a new one
 *  @param        copy           copy data if true, move data otherwise
 *  @param        max_blob_size  reject if sum(blob.size) > max_blob_size
 *                               to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PBlobList_t *PBlobList_from_bloblist(
        bloblist_t *list,
        PBlobList_t *result,
        bool copy,
        size_t max_blob_size
    );


/**
 *  <!--       PBlobList_to_bloblist()       -->
 *  
 *  @brief Convert ASN.1 PBlobList_t to bloblist_t
 *  
 *  @param[in]     list          ASN.1 PBlobList_t to convert
 *  @param[in,out] result        bloblist_t to update or NULL to alloc a new one
 *  @param         copy          copy data if true, move data otherwise
 *  @param         max_blob_size reject if sum(blob.size) > max_blob_size
 *                               to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

bloblist_t *PBlobList_to_bloblist(
        PBlobList_t *list,
        bloblist_t *result,
        bool copy,
        size_t max_blob_size
    );


/**
 *  <!--       ASN1Message_from_message()       -->
 *  
 *  @brief Convert message into ASN.1 ASN1Message_t
 *  
 *  @param[in] msg            message to convert
 *  @param[in,out] result     ASN1Message_t to update or NULL to alloc a new one
 *  @param copy               copy data if true, move data otherwise
 *  @param max_blob_size      reject if sum(blob.size) > max_blob_size
 *                            to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

DYNAMIC_API
ASN1Message_t *ASN1Message_from_message(
        message *msg,
        ASN1Message_t *result,
        bool copy,
        size_t max_blob_size
    );


/**
 *  <!--       ASN1Message_to_message()       -->
 *  
 *  @brief Convert ASN.1 ASN1Message_t to message
 *  
 *  @param[in] 		msg            	ASN.1 ASN1Message_t to convert
 *  @param[in,out] 	result  	message to update or NULL to alloc a new one
 *  @param 		copy            copy data if true, move data otherwise
 *  @param		max_blob_size   reject if sum(blob.size) > max_blob_size
 *                                      to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

DYNAMIC_API
message *ASN1Message_to_message(
        ASN1Message_t *msg,
        message *result,
        bool copy,
        size_t max_blob_size
    );


#ifdef __cplusplus
}
#endif

#endif
