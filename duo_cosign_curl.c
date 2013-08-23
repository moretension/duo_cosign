/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include <sys/types.h>

#include "duo_cosign_curl.h"

dc_curlopt_t	dc_opt_table[]  = {
    { CURLOPT_HTTPAUTH, DC_CURLOPT_TYPE_INT, .val_int = CURLAUTH_BASIC },
    { CURLOPT_HTTPHEADER, DC_CURLOPT_TYPE_PTR, .val_ptr = NULL },
    { CURLOPT_PASSWORD, DC_CURLOPT_TYPE_PTR, .val_ptr = NULL },
    { CURLOPT_SSL_VERIFYPEER, DC_CURLOPT_TYPE_INT, .val_int = 1 },
    { CURLOPT_TIMEOUT, DC_CURLOPT_TYPE_INT, .val_int = 60L },
    { CURLOPT_URL, DC_CURLOPT_TYPE_PTR, .val_ptr = NULL },
    { CURLOPT_USERNAME, DC_CURLOPT_TYPE_PTR, .val_ptr = NULL },
    { CURLOPT_VERBOSE, DC_CURLOPT_TYPE_INT, .val_int = 0 },
    { CURLOPT_WRITEDATA, DC_CURLOPT_TYPE_PTR, .val_ptr = NULL },
    { CURLOPT_WRITEFUNCTION, DC_CURLOPT_TYPE_PTR, .val_ptr = NULL },
};

#define DC_CURLOPT_TABLE_SIZE \
	sizeof( dc_opt_table ) / sizeof( dc_opt_table[ 0 ] )

    int
dc_curl_set_options( CURL *curl )
{
    CURLcode		rc = CURLE_OK;
    int			i;

    for ( i = 0; i < DC_CURLOPT_TABLE_SIZE; i++ ) {
	if ( dc_opt_table[ i ].type == DC_CURLOPT_TYPE_PTR ) {
	    rc = curl_easy_setopt( curl, dc_opt_table[ i ].opt,
				dc_opt_table[ i ].val_ptr );
	} else if ( dc_opt_table[ i ].type == DC_CURLOPT_TYPE_INT ) {
	    rc = curl_easy_setopt( curl, dc_opt_table[ i ].opt,
				dc_opt_table[ i ].val_int );
	}

	if ( rc != CURLE_OK ) {
	    fprintf( stderr, "curl_easy_setopt %d failed: %s\n",
			dc_opt_table[ i ].opt, curl_easy_strerror( rc ));
	    break;
	}
    }

    return( rc );
}
