/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include "duo_cosign_json.h"

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
