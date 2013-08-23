/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/hmac.h>

#include <curl/curl.h>

#include "duo_cosign_api.h"
#include "duo_cosign_cfg.h"
#include "duo_cosign_curl.h"

extern int		errno;

    static char *
dc_get_cfg_path( void )
{
    char	*path = NULL;

    path = getenv( DC_CFG_PATH_ENV_NAME );
    if ( path == NULL ) {
	path = DC_CFG_PATH_DEFAULT;
    }

    return( path );
}

    static char *
dc_read_input_line( void )
{
    char		buf[ 512 ];
    char		*line;
    int			len;

    if ( fgets( buf, sizeof( buf ), stdin ) == NULL ) {
	fprintf( stderr, "fgets failed: %s\n", strerror( errno ));
	exit( 2 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	fprintf( stderr, "fgets failed: line too long\n" );
	exit( 2 );
    }
    buf[ len - 1 ] = '\0';

    if (( line = strdup( buf )) == NULL ) {
	fprintf( stderr, "strdup failed: %s\n", strerror( errno ));
	exit( 2 );
    }

    return( line );
}
    
    int
main( int ac, char *av[] )
{
    CURL		*hcurl;
    CURLcode		rc;
    struct curl_slist	*headers = NULL;
    dc_data_t		dc_response_buf = { 0, NULL };
    char		buf[ DC_API_RESPONSE_MAX ];
    char		hmac_hex[ EVP_MAX_MD_SIZE * 2 + 2 ];
    char		date[ 40 ];
    dc_cfg_entry_t	*cfg_list = NULL;
    dc_param_t		*params = NULL;
    char		*cfg_path;
    char		*api_url = NULL;
    char		*user = NULL;
    char		*device = NULL;
    int			status;

    cfg_path = dc_get_cfg_path();

    status = dc_cfg_read( cfg_path, &cfg_list );
    if ( status < 0 ) {
	fprintf( stderr, "duo_cosign: failed to read config %s\n", cfg_path );
	exit( 2 );
    }

    if ( curl_global_init( CURL_GLOBAL_ALL ) != 0 ) {
	fprintf( stderr, "curl_global_init failed\n" );
	exit( 2 );
    }

    user = dc_read_input_line();
    device = dc_read_input_line();

    if ( dc_api_request_dispatch( DC_PING_URL_REF_ID, NULL, cfg_list ) < 0 ) {
	exit( 2 );
    }
    if ( dc_api_request_dispatch( DC_CHECK_URL_REF_ID, NULL, cfg_list ) < 0 ) {
	exit( 2 );
    }

    if ( user != NULL ) {
	DC_PARAMS_ADD( &params, USERNAME, user );
	dc_api_request_dispatch( DC_PREAUTH_URL_REF_ID, params, cfg_list );
	dc_param_list_free( &params );

	DC_PARAMS_ADD( &params, USERNAME, user );
	DC_PARAMS_ADD( &params, FACTOR, "push" );
	DC_PARAMS_ADD( &params, DEVICE, device );
	dc_api_request_dispatch( DC_AUTH_URL_REF_ID, params, cfg_list );
	dc_param_list_free( &params );
    }

    free( user );

    curl_global_cleanup();

    return( 0 );
}

