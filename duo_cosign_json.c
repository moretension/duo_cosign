/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include "config.h"

#include <assert.h>
#include <string.h>

#include "duo_cosign_json.h"
#include "duo_cosign_api.h"

    static inline dc_json_t *
_dc_json_parse( char *buf, int len, dc_json_err_t *err )
{
    return( json_loadb( buf, len, 0, (json_error_t *)err ));
}

#ifdef notdef
    static inline dc_json_t *
_dc_json_parse( char *buf, int len, dc_json_err_t *err )
{
    fprintf( stderr, "No JSON parser compiled\n" );
    abort();
}
#endif /* defined(JANSSON_H) */

    dc_json_t *
duo_cosign_json_parse( char *buf, int len, dc_json_err_t *j_err )
{
    return( _dc_json_parse( buf, len, j_err ));
}

    int
duo_cosign_json_get_response( dc_json_t *jsn, void *r )
{
    dc_json_t		*j;
    dc_response_t	*resp;
    const char		*s;
    int			i;
    struct {
	const char	*status_str;
	dc_status_t	status;
    } status_tab[] = {
	{ DC_STATUS_OK_STR, DC_STATUS_OK },
	{ DC_STATUS_FAIL_STR, DC_STATUS_REQ_FAIL },
	{ NULL, -1 },
    };

    assert( r != NULL );

    resp = (dc_response_t *)r;
    memset( resp, 0, sizeof( dc_response_t ));
    
    j = json_object_get( jsn, DC_RESPONSE_STAT_KEY );
    if ( j == NULL ) {
	return( -1 );
    }

    s = json_string_value( j );
    if ( s == NULL ) {
	fprintf( stderr, "Invalid type for %s key in response\n",
		DC_RESPONSE_STAT_KEY );
	return( -1 );
    }

    for ( i = 0; status_tab[ i ].status_str != NULL; i++ ) {
	if ( strcmp( s, status_tab[ i ].status_str ) == 0 ) {
	    break;
	}
    }
    if ( status_tab[ i ].status_str == NULL ) {
	fprintf( stderr, "Invalid value \"%s\" for %s key in response\n",
		s, DC_RESPONSE_STAT_KEY );
	return( -1 );
    }
    resp->status = status_tab[ i ].status;

    if ( resp->status == DC_STATUS_REQ_FAIL ) {
	resp->type = DC_RESPONSE_TYPE_ERROR;

	j = json_object_get( jsn, DC_RESPONSE_CODE_KEY );
	resp->response_error.code = json_integer_value( j );

	j = json_object_get( jsn, DC_RESPONSE_MESSAGE_KEY );
	resp->response_error.message = json_string_value( j );

	j = json_object_get( jsn, DC_RESPONSE_MESSAGE_DETAIL_KEY );
	resp->response_error.detail = json_string_value( j );

	return( 0 );
    }

    j = json_object_get( jsn, DC_RESPONSE_RESPONSE_KEY );
    switch ( json_typeof( j )) {
    case JSON_OBJECT:
	resp->type = DC_RESPONSE_TYPE_OBJECT;
	resp->response_object = j;
	break;

    case JSON_STRING:
	resp->type = DC_RESPONSE_TYPE_STRING;
	resp->response_string = json_string_value( j );
	break;

    default:
	fprintf( stderr, "Invalid type for %s key in response\n",
		DC_RESPONSE_RESPONSE_KEY );
	return( -1 );
    }

    return( 0 );
}
