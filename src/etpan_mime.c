#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "etpan_mime.h"

#define MAX_MESSAGE_ID 512

static char * generate_boundary(const char * boundary_prefix)
{
    char id[MAX_MESSAGE_ID];
    time_t now;
    char name[MAX_MESSAGE_ID];
    long value;
 
    id[MAX_MESSAGE_ID - 1] = 0;
    name[MAX_MESSAGE_ID - 1] = 0;

    now = time(NULL);
#ifndef WIN32
    value = random();
    
    gethostname(name, MAX_MESSAGE_ID - 1);
#else
    value = now;
    strcpy(name, "WINDOWS");
#endif
    
    if (boundary_prefix == NULL)
        boundary_prefix = "";
    
    snprintf(id, MAX_MESSAGE_ID, "%s%lx_%lx_%x", boundary_prefix, now, value,
            getpid());
    
    return strdup(id);
}

struct mailmime * part_new_empty(
        struct mailmime_content * content,
        struct mailmime_fields * mime_fields,
        const char * boundary_prefix,
        int force_single
    )
{
	struct mailmime * build_info;
	clist * list;
	int r;
	int mime_type;

	list = NULL;

	if (force_single) {
		mime_type = MAILMIME_SINGLE;
	}
	else {
		switch (content->ct_type->tp_type) {
			case MAILMIME_TYPE_DISCRETE_TYPE:
			mime_type = MAILMIME_SINGLE;
			break;

			case MAILMIME_TYPE_COMPOSITE_TYPE:
			switch (content->ct_type->tp_data.tp_composite_type->ct_type) {
				case MAILMIME_COMPOSITE_TYPE_MULTIPART:
				mime_type = MAILMIME_MULTIPLE;
				break;

				case MAILMIME_COMPOSITE_TYPE_MESSAGE:
				if (strcasecmp(content->ct_subtype, "rfc822") == 0)
					mime_type = MAILMIME_MESSAGE;
				else
					mime_type = MAILMIME_SINGLE;
				break;

				default:
				goto err;
			}
			break;

			default:
			goto err;
		}
	}

	if (mime_type == MAILMIME_MULTIPLE) {
		char * attr_name;
		char * attr_value;
		struct mailmime_parameter * param;
		clist * parameters;
		char * boundary;

		list = clist_new();
		if (list == NULL)
			goto err;

		attr_name = strdup("boundary");
		boundary = generate_boundary(boundary_prefix);
		attr_value = boundary;
		if (attr_name == NULL) {
			free(attr_name);
			goto free_list;
		}

		param = mailmime_parameter_new(attr_name, attr_value);
		if (param == NULL) {
			free(attr_value);
			free(attr_name);
			goto free_list;
		}

		if (content->ct_parameters == NULL) {
			parameters = clist_new();
			if (parameters == NULL) {
				mailmime_parameter_free(param);
				goto free_list;
			}
		}
		else
			parameters = content->ct_parameters;

		r = clist_append(parameters, param);
		if (r != 0) {
			clist_free(parameters);
			mailmime_parameter_free(param);
			goto free_list;
		}

		if (content->ct_parameters == NULL)
			content->ct_parameters = parameters;
	}

	build_info = mailmime_new(mime_type,
		NULL, 0, mime_fields, content,
		NULL, NULL, NULL, list,
		NULL, NULL);
	if (build_info == NULL) {
		clist_free(list);
		return NULL;
	}

	return build_info;

	free_list:
	clist_free(list);
	err:
	return NULL;
}

struct mailmime * get_text_part(
        const char * mime_type,
        const char * text,
        size_t length,
        int encoding_type
    )
{
	struct mailmime_fields * mime_fields;
	struct mailmime * mime;
	struct mailmime_content * content;
	struct mailmime_parameter * param;
	struct mailmime_disposition * disposition;
	struct mailmime_mechanism * encoding;
    
	encoding = mailmime_mechanism_new(encoding_type, NULL);
	disposition = mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_INLINE,
		NULL, NULL, NULL, NULL, (size_t) -1);
	mime_fields = mailmime_fields_new_with_data(encoding,
		NULL, NULL, disposition, NULL);

	content = mailmime_content_new_with_str(mime_type);
	param = mailmime_param_new_with_data("charset", "utf-8");
	clist_append(content->ct_parameters, param);
	mime = part_new_empty(content, mime_fields, NULL, 1);
	mailmime_set_body_text(mime, (char *) text, length);
	
	return mime;
}

struct mailmime * part_multiple_new(
        const char * type,
        const char * boundary_prefix
    )
{
    struct mailmime_fields * mime_fields;
    struct mailmime_content * content;
    struct mailmime * mp;
    
    mime_fields = mailmime_fields_new_empty();
    if (mime_fields == NULL)
        goto err;
    
    content = mailmime_content_new_with_str(type);
    if (content == NULL)
        goto free_fields;
    
    mp = part_new_empty(content, mime_fields, boundary_prefix, 0);
    if (mp == NULL)
        goto free_content;
    
    return mp;
    
free_content:
    mailmime_content_free(content);
free_fields:
    mailmime_fields_free(mime_fields);
err:
    return NULL;
}

