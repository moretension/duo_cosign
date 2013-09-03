/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#ifndef DUO_COSIGN_JSON_H
#define DUO_COSIGN_JSON_H

#include <jansson.h>

#if defined(JANSSON_H)
#define dc_json_t	json_t
#define dc_json_err_t	json_error_t
#else /* !defined(JANSSON_H) */
#error No JSON parser detected
#endif /* defined(JANSSON_H) */


dc_json_t	*duo_cosign_json_parse( char *, int, dc_json_err_t * );


#endif /* DUO_COSIGN_JSON_H */
