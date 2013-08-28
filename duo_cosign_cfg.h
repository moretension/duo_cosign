/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#ifndef DUO_COSIGN_CFG_H
#define DUO_COSIGN_CFG_H

#define DC_CFG_LINE_FS		"="

#define DC_CFG_PATH_ENV_NAME	"DUO_COSIGN_CFG"
#define DC_CFG_PATH_DEFAULT	"./duo_cosign.cfg"

#define DC_CFG_KEY_API_HOST	"host"
#define DC_CFG_KEY_API_IKEY	"ikey"
#define DC_CFG_KEY_API_SKEY	"skey"

#define DC_CFG_API_HOST(c) \
	dc_cfg_value_for_key((c), DC_CFG_KEY_API_HOST )
#define DC_CFG_API_IKEY(c) \
	dc_cfg_value_for_key((c), DC_CFG_KEY_API_IKEY )
#define DC_CFG_API_SKEY(c) \
	dc_cfg_value_for_key((c), DC_CFG_KEY_API_SKEY )

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
