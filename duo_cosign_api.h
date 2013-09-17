/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#ifndef DUO_COSIGN_API_H
#define DUO_COSIGN_API_H

#include <time.h>

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
    DC_STATUS_OK = 0,
    DC_STATUS_REQ_FAIL,
    DC_STATUS_FAIL,
    DC_STATUS_AUTH_REQUIRED,
    DC_STATUS_AUTH_PENDING,
    DC_STATUS_USER_ALLOWED,
    DC_STATUS_USER_DENIED,
    DC_STATUS_USER_NOT_ENROLLED,
} dc_status_t;

#define DC_STATUS_OK_STR		"OK"
#define DC_STATUS_FAIL_STR		"FAIL"
#define DC_STATUS_AUTH_REQUIRED_STR	"auth"
#define DC_STATUS_AUTH_PENDING_STR	"waiting"
#define DC_STATUS_USER_ALLOWED_STR	"allow"
#define DC_STATUS_USER_DENIED_STR	"deny"
#define DC_STATUS_USER_NOT_ENROLLED_STR	"enroll"

typedef enum {
    DC_RESPONSE_TYPE_OBJECT = 0,
    DC_RESPONSE_TYPE_STRING,
    DC_RESPONSE_TYPE_ERROR,
} dc_response_type_t;

struct dc_response {
    dc_status_t		status;
    dc_response_type_t	type;
    union {
	void		*response_obj;
#define response_object	u.response_obj
	const char	*response_str;
#define response_string	u.response_str
	struct {
	    int		code;
	    const char	*message;
	    const char	*detail;
	} response_err;
#define response_error	u.response_err
    } u;
};
typedef struct dc_response	dc_response_t;

#define DC_RESPONSE_CODE_KEY		"code"
#define DC_RESPONSE_MESSAGE_KEY		"message"
#define DC_RESPONSE_MESSAGE_DETAIL_KEY	"message_detail"
#define DC_RESPONSE_RESPONSE_KEY	"response"
#define DC_RESPONSE_STAT_KEY		"stat"

#define DC_RESPONSE_TIME_KEY		"time"


typedef enum {
    DC_DEVICE_TYPE_UNKNOWN = 0,
    DC_DEVICE_TYPE_PHONE = 1,
    DC_DEVICE_TYPE_TOKEN,
    DC_DEVICE_TYPE_DESKTOPTOKEN,
} dc_device_type_t;

#define DC_DEVICE_TYPE_PHONE_KEY	"phone"
#define DC_DEVICE_TYPE_TOKEN_KEY	"token"
#define DC_DEVICE_TYPE_DESKTOPTOKEN_KEY	"desktoptoken"

typedef enum {
    DC_DEVICE_CAPA_NONE = 0,
    DC_DEVICE_CAPA_PUSH = (1 << 0),
    DC_DEVICE_CAPA_PHONE = (1 << 1),
    DC_DEVICE_CAPA_SMS = (1 << 2),
} dc_device_capa_t;

#define DC_DEVICE_CAPA_PUSH_KEY		"push"
#define DC_DEVICE_CAPA_PHONE_KEY	"phone"
#define DC_DEVICE_CAPA_SMS_KEY		"sms"

#define DC_DEVICE_CAPABILITIES_KEY	"capabilities"
#define DC_DEVICE_DISPLAY_NAME_KEY	"display_name"
#define DC_DEVICE_ID_KEY		"device"
#define DC_DEVICE_NAME_KEY		"name"
#define DC_DEVICE_NEXT_SMS_PASSCODE_KEY	"next_sms_passcode"
#define DC_DEVICE_NUMBER_KEY		"number"
#define DC_DEVICE_TYPE_KEY		"type"

struct dc_device {
    struct dc_device		*next;

    dc_device_type_t		type;
    dc_device_capa_t		capabilities;
    const char			*id;
    const char			*display_name;	
    const char			*name;
    const char			*next_sms_passcode;
    const char			*number;
};
typedef struct dc_device	dc_device_t;

char	*dc_device_list_json_serialize( dc_device_t * );

struct dc_preauth_result {
    dc_status_t			result;
    const char			*status_msg;
    const char			*enroll_url;
    dc_device_t			*devices;
};
typedef struct dc_preauth_result	dc_preauth_result_t;

#define DC_PREAUTH_RESULT_KEY		"result"
#define DC_PREAUTH_STATUS_MSG_KEY	"status_msg"
#define DC_PREAUTH_ENROLL_URL_KEY	"enroll_portal_url"
#define DC_PREAUTH_DEVICES_KEY		"devices"

struct dc_auth {
    char			*user;
    char			*factor;
    char			*data;
    char			*ipaddr;
    int				async;
};
typedef struct dc_auth		dc_auth_t;

#define DC_AUTH_PUSH_DEVICE_KEY		"device"
#define DC_AUTH_PUSH_TYPE_KEY		"type"
#define DC_AUTH_PUSH_DISPLAY_USERNAME_KEY	"display_username"
#define DC_AUTH_PUSH_PUSHINFO_KEY	"pushinfo"

struct dc_auth_result {
    int				async;
    dc_status_t			result;
    const char			*status;
    const char			*status_msg;
    const char			*txid;
};
typedef struct dc_auth_result	dc_auth_result_t;

#define DC_AUTH_RESULT_KEY	DC_PREAUTH_RESULT_KEY
#define DC_AUTH_STATUS_KEY	"status"
#define DC_AUTH_STATUS_MSG_KEY	DC_PREAUTH_STATUS_MSG_KEY
#define DC_AUTH_TXID_KEY	"txid"

typedef enum {
    DC_PARAM_TYPE_INT,
    DC_PARAM_TYPE_STR,
    DC_PARAM_TYPE_PTR,
} dc_param_type_t; 
#define DC_PARAM_TYPE_MAX	DC_PARAM_TYPE_STR

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
#define DC_PARAM_KEY_TXID		"txid"
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
char	*dc_api_url_for_request( duo_cosign_api_t *req, char * );
int	dc_api_request_dispatch( dc_url_ref_id_t, dc_param_t *,
				dc_cfg_entry_t *, dc_response_t * );

/* convenience wrappers */
int	dc_ping( dc_cfg_entry_t *, time_t * );
int	dc_check( dc_cfg_entry_t *, time_t * );
int	dc_preauth( dc_cfg_entry_t *, char *, dc_preauth_result_t * );
void	dc_preauth_result_clear( dc_preauth_result_t * );
int	dc_auth( dc_cfg_entry_t *, dc_auth_t *, dc_auth_result_t * );
int	dc_auth_status( dc_cfg_entry_t *, char *, char *, dc_auth_result_t * );

#endif /* DUO_COSIGN_API_H */
