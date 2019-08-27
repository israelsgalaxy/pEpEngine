// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>

#include "stringlist.h"

#include "test_util.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for StringlistTest
    class StringlistTest : public ::testing::Test {};

}  // namespace


TEST_F(StringlistTest, check_stringlists) {
    output_stream << "\n*** data structures: stringlist_test ***\n\n";

    const char* str0 = "I am your father, Luke\n";

    // new_stringlist test code
    output_stream << "creating one-element stringlist…\n";

    stringlist_t* src = new_stringlist(str0);
    ASSERT_NE((src), nullptr);
    ASSERT_STREQ(src->value, str0);
    output_stream << "Value: " << src->value;
    ASSERT_EQ(src->next, nullptr);
    output_stream << "one-element stringlist created, next element is NULL\n";

    output_stream << "freeing stringlist…\n\n";
    free_stringlist(src);
    src = NULL;

    // test stringlist_add with four-element list
    output_stream << "creating four-element stringlist…\n";
    const char* str1 = "String 1";
    const char* str2 = "\tString 2";
    const char* str3 = "\tString 3";
    const char* str4 = "\tString 4\n";
    const char* strarr[4] = {str1, str2, str3, str4};
    output_stream << "stringlist_add on empty list…\n";
    src = stringlist_add(src, str1); // src is NULL
    ASSERT_NE(src, nullptr);
    ASSERT_NE(stringlist_add(src, str2), nullptr); // returns ptr to new elt
    ASSERT_NE(stringlist_add(src, str3), nullptr);
    ASSERT_NE(stringlist_add(src, str4), nullptr);

    output_stream << "checking contents\n";
    stringlist_t* p = src;
    int i = 0;
    while (p) {
        ASSERT_NE((p->value), nullptr);
        ASSERT_STREQ(p->value, strarr[i]);
        ASSERT_NE(p->value , strarr[i]); // ensure this is a copy
        p = p->next;
        i++;
    }
    ASSERT_EQ(p, nullptr); // list ends properly

    output_stream << "\nduplicating four-element stringlist…\n";
    stringlist_t* dst = stringlist_dup(src);
    ASSERT_NE(dst, nullptr);

    stringlist_t* p_dst = dst;
    p = src;

    output_stream << "checking contents\n";
    while (p_dst) {
        ASSERT_NE(p_dst->value, nullptr);
        ASSERT_STREQ(p->value, p_dst->value);
        ASSERT_NE(p->value , p_dst->value); // ensure this is a copy
        output_stream << p_dst->value;
        p = p->next;
        p_dst = p_dst->next;
        ASSERT_TRUE((p == NULL) == (p_dst == NULL));
    }
    ASSERT_EQ(p_dst, nullptr);

    output_stream << "freeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);
    src = NULL;
    dst = NULL;

    output_stream << "duplicating one-element stringlist…\n";
    src = new_stringlist(str0);
    ASSERT_NE(src, nullptr);
    dst = stringlist_dup(src);
    ASSERT_STREQ(dst->value, str0);
    output_stream << "Value: " << src->value;
    ASSERT_EQ(dst->next, nullptr);
    output_stream << "one-element stringlist duped, next element is NULL\n";

    output_stream << "\nAdd to empty stringlist (node exists, but no value…)\n";
    if (src->value)
        free(src->value);
    src->value = NULL;
    stringlist_add(src, str2);
    ASSERT_NE(src->value, nullptr);
    ASSERT_STREQ(src->value, str2);
    ASSERT_NE(src->value , str2); // ensure this is a copy
    output_stream << src->value;

    output_stream << "\nfreeing stringlists…\n\n";
    free_stringlist(src);
    free_stringlist(dst);

    src = NULL;
    dst = NULL;

    output_stream << "done.\n";
}

TEST_F(StringlistTest, check_dedup_stringlist) {
    const char* str1 = "Your Mama";
    const char* str2 = "And your Papa";
    const char* str3 = "And your little dog too!";
    const char* str4 = "Meh";

    stringlist_t* s_list = NULL;
    dedup_stringlist(s_list);
    ASSERT_EQ(s_list , nullptr);

    s_list = new_stringlist(NULL);
    dedup_stringlist(s_list);
    ASSERT_EQ(s_list->value , nullptr);

    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_EQ(s_list->next, nullptr);

    // Add same value
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_EQ(s_list->next, nullptr);

    stringlist_add(s_list, str1);
    stringlist_add(s_list, str2);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);
    ASSERT_EQ(s_list->next->next, nullptr);
    ASSERT_NE(s_list->next->value, nullptr);
    ASSERT_STREQ(s_list->next->value, str2);

    free_stringlist(s_list);
    s_list = new_stringlist(str1);

    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_EQ(s_list->next, nullptr);

    free_stringlist(s_list);
    s_list = new_stringlist(str1);

    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str2);
    stringlist_add(s_list, str1);
    dedup_stringlist(s_list);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str1);
    ASSERT_NE(s_list->next, nullptr);
    ASSERT_EQ(s_list->next->next, nullptr);
    ASSERT_NE(s_list->next->value, nullptr);
    ASSERT_STREQ(s_list->next->value, str2);

    free_stringlist(s_list);
    s_list = new_stringlist(str3);

    stringlist_add(s_list, str2);
    stringlist_add(s_list, str3);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str3);
    stringlist_add(s_list, str2);
    stringlist_add(s_list, str1);
    stringlist_add(s_list, str4);
    stringlist_add(s_list, str3);

    dedup_stringlist(s_list);
    ASSERT_NE(s_list->next, nullptr);
    ASSERT_NE(s_list->next->next, nullptr);
    ASSERT_NE(s_list->next->next->next, nullptr);
    ASSERT_EQ(s_list->next->next->next->next, nullptr);
    ASSERT_NE(s_list->value, nullptr);
    ASSERT_STREQ(s_list->value, str3);
    ASSERT_NE(s_list->next->value, nullptr);
    ASSERT_STREQ(s_list->next->value, str2);
    ASSERT_NE(s_list->next->next->value, nullptr);
    ASSERT_STREQ(s_list->next->next->value, str1);
    ASSERT_NE(s_list->next->next->next->value, nullptr);
    ASSERT_STREQ(s_list->next->next->next->value, str4);
}