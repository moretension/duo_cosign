/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#ifndef DUO_COSIGN_API_H
#define DUO_COSIGN_API_H

#include "duo_cosign_cfg.h"

#define DC_API_RESPONSE_MAX		8192
	
#define DC_PING_URL_REF			"/auth/v2/ping"
#define DC_CHECK_URL_REF		"/auth/v2/check"
#define DC_ENROLL_URL_REF		"/auth/v2/enroll"
#define DC_ENROLL_STATUS_URL_REF	"/auth/v2/enroll_status"
#define DC_PREAUTH_URL_REF		"/auth/v2/preauth"
#define DC_AUTH_URL_REF			"/auth/v2/auth"
#define DC_AUTH_STATUS_URL_REF		"/auth/v2/auth_status"

typedef enum {
    DC_PING_URL_REF_ID = 0,
    DC_CHECK_URL_REF_ID,
    DC_ENROLL_URL_REF_ID,
    DC_ENROLL_STATUS_URL_REF_ID,
    DC_PREAUTH_URL_REF_ID,
    DC_AUTH_URL_REF_ID,
    DC_AUTH_STATUS_URL_REF_ID,
} dc_url_ref_id_t;

#define DC_API_GET	"GET"
#define DC_API_POST	"POST"

#define DC_API_DATE_FORMAT_DEFAULT	0
#define DC_API_DATE_FORMAT_HEADER	(1 << 0)

struct dc_data {
    size_t		len;
    char		*data;
};
typedef struct dc_data	dc_data_t;

typedef enum {
    DC_PARAM_TYPE_INT,
    DC_PARAM_TYPE_STR,
    DC_PARAM_TYPE_PTR,
} dc_param_type_t; 
#define DC_PARAM_TYPE_MAX	DC_PARAM_TYPE_STR

#define DC_MAX_PARAMS		8
struct dc_param {
    struct dc_param	*next;
    dc_param_type_t	type;
    char		*name;

    union {
	int		p_int;
#define dc_intval	val_u.p_int
	char		*p_str;
#define dc_strval	val_u.p_str
	void		*p_ptr;
#define dc_ptrval	val_u.p_ptr
    } val_u;
};
typedef struct dc_param	dc_param_t;

int	dc_param_list_push( dc_param_t **, char *, dc_param_type_t, ... );
void	dc_param_list_free( dc_param_t ** );

#define DC_PARAMS_PUSH_INT(p1, n1, i1) \
	dc_param_list_push((p1), (n1), DC_PARAM_TYPE_INT, (i1))
#define DC_PARAMS_PUSH_STR(p1, n1, s1) \
	dc_param_list_push((p1), (n1), DC_PARAM_TYPE_STR, (s1))

#define DC_PARAM_KEY_ACTIVATIONCODE	"activation_code"
#define DC_PARAM_KEY_ASYNC		"async"
#define DC_PARAM_KEY_DEVICE		"device"
#define DC_PARAM_KEY_DISPLAYUSERNAME	"display_username"
#define DC_PARAM_KEY_FACTOR		"factor"
#define DC_PARAM_KEY_IPADDR		"ipaddr"
#define DC_PARAM_KEY_PASSCODE		"passcode"
#define DC_PARAM_KEY_PUSHINFO		"pushinfo"
#define DC_PARAM_KEY_TYPE		"type"
#define DC_PARAM_KEY_USERNAME		"username"
#define DC_PARAM_KEY_USERID		"user_id"
#define DC_PARAM_KEY_VALIDSECS		"valid_secs"

#define DC_PARAMS_ADD1(p1, k1, v1) \
	DC_PARAMS_PUSH_STR((p1), DC_PARAM_KEY_##k1, (v1)) 
#define DC_PARAMS_ADD(p1, k1, v1) \
	DC_PARAMS_ADD1((p1), k1, (v1))

struct duo_cosign_api {
    const char		*url_ref;
    dc_url_ref_id_t	url_ref_id;
    const char		*method;
    char		*(*param_fn)( void *, dc_param_t * );
};
typedef struct duo_cosign_api	duo_cosign_api_t;

extern duo_cosign_api_t		dc_api[];
extern char			*dc_api_hostname;

char	*dc_api_get_hostname( void );
char	*dc_api_set_hostname( char * );

int	dc_api_get_formatted_date( char *, int, int );
int	dc_api_hmac_for_request( duo_cosign_api_t *, dc_cfg_entry_t *,
				char *, char *, int );
char	*dc_api_url_for_request( duo_cosign_api_t *req );
int	dc_api_request_dispatch( dc_url_ref_id_t, dc_param_t *,
				dc_cfg_entry_t * );

#endif /* DUO_COSIGN_API_H */
