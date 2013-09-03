AUTOMAKE_OPTIONS = foreign

CFLAGS = -Wall
LDFLAGS = 

bin_PROGRAMS = dc_api
dc_api_SOURCES = duo_cosign.c duo_cosign_api.c duo_cosign_cfg.c \
			duo_cosign_curl.c duo_cosign_json.c
dc_api_CPPFLAGS = -I$(JSON_INCLUDE)
dc_api_LDADD = -lcurl -lcrypto $(JSON_STATIC_LIB)
dc_api_DEPENDENCIES=
