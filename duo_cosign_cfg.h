/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#ifndef DUO_COSIGN_CFG_H
#define DUO_COSIGN_CFG_H

#define DC_CFG_LINE_FS		"="

#define DC_CFG_PATH_ENV_NAME	"DUO_COSIGN_CFG"
#define DC_CFG_PATH_DEFAULT	"./duo_cosign.cfg"

#define DC_CFG_KEY_API_HOST		"host"
#define DC_CFG_KEY_API_IKEY		"ikey"
#define DC_CFG_KEY_API_SKEY		"skey"
#define DC_CFG_KEY_FACTOR_NAME		"factor name"
#define DC_CFG_KEY_AUTH_REQUEST_PREFIX	"request prefix"
#define DC_CFG_KEY_DISPLAY_ERROR_MSG	"show errors"

#define DC_CFG_VALUE1(c, k) \
	dc_cfg_value_for_key((c), DC_CFG_KEY_##k)
#define DC_CFG_VALUE(c, k) \
	DC_CFG_VALUE1((c), k)

#define _DC_FACTOR_NAME		"Duo"

struct dc_cfg_entry {
    struct dc_cfg_entry	*next;
    char		*key;
    char		*val;
};
typedef struct dc_cfg_entry	dc_cfg_entry_t;

char	*dc_get_cfg_path( void );
int	dc_cfg_read( char *, dc_cfg_entry_t ** );
void	dc_cfg_free( dc_cfg_entry_t ** );

char	*dc_cfg_value_for_key( dc_cfg_entry_t *, char * );

#endif /* DUO_COSIGN_CFG_H */
