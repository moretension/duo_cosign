/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include <curl/curl.h>

typedef enum {
    DC_CURLOPT_TYPE_PTR,
    DC_CURLOPT_TYPE_INT,
} dc_curlopt_type_t;

enum {
    DC_OPT_HTTPAUTH_IDX = 0,
    DC_OPT_HTTPHEADER_IDX,
    DC_OPT_PASSWORD_IDX,
    DC_OPT_SSL_VERIFYPEER_IDX,
    DC_OPT_TIMEOUT_IDX,
    DC_OPT_URL_IDX,
    DC_OPT_USERNAME_IDX,
    DC_OPT_VERBOSE_IDX,
    DC_OPT_WRITEDATA_IDX,
    DC_OPT_WRITEFUNCTION_IDX,
};

struct dc_curlopt {
    CURLoption		opt;
    dc_curlopt_type_t	type;

    union {
	void		*val_ptr;
#define val_ptr		val_u.val_ptr
	int		val_int;
#define val_int		val_u.val_int
    } val_u;
};
typedef struct dc_curlopt	dc_curlopt_t;

#define DC_CURL_SET_HEADERS(x) \
	dc_opt_table[ DC_OPT_HTTPHEADER_IDX ].val_ptr = (x)
#define DC_CURL_SET_PASSWORD(x) \
	dc_opt_table[ DC_OPT_PASSWORD_IDX ].val_ptr = (x)
#define DC_CURL_SET_RESPONSE_BUFFER(x) \
	dc_opt_table[ DC_OPT_WRITEDATA_IDX ].val_ptr = (x)
#define DC_CURL_SET_RESPONSE_CALLBACK(x) \
	dc_opt_table[ DC_OPT_WRITEFUNCTION_IDX ].val_ptr = (x)
#define DC_CURL_SET_URL(x) \
	dc_opt_table[ DC_OPT_URL_IDX ].val_ptr = (x)
#define DC_CURL_SET_USERNAME(x) \
	dc_opt_table[ DC_OPT_USERNAME_IDX ].val_ptr = (x)

extern dc_curlopt_t		dc_opt_table[];

int	dc_curl_set_options( CURL * );

