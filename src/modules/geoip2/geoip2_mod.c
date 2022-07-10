/**
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


#include "../../core/sr_module.h"
#include "../../core/dprint.h"
#include "../../core/ut.h"
#include "../../core/pvar.h"
#include "../../core/kemi.h"
#include "../../core/mod_fix.h"

#include "geoip2_pv.h"

MODULE_VERSION

#define pi 3.14159265358979323846
#define MAX_TENANT_ENTRIES  512
#define STR_LOCATION_LEN 128
#define MAX_LOCATION_PER_TENANT 5
#define GEOIP_CC_INDIA "IN"

#define geoip_tenant_tbl_index(_h)  ((_h)&((MAX_TENANT_ENTRIES)-1))

typedef struct _geoip_tenant_info {
    unsigned int loc_count;
    double range;
    char type;
    char reserved[3];
    char realm[128];
    char *locs[MAX_LOCATION_PER_TENANT];
} geoip_tenant_info_t;

typedef struct _geoip_tenant_tbl {
    unsigned int num_entries;
    geoip_tenant_info_t *entries; 
} geoip_tenant_tbl_t;

static char *geoip2_path = NULL;
static char *geoip2_tenant_table_path = NULL;
static geoip_tenant_tbl_t *g_tenant_tbl = NULL;

static int  mod_init(void);
static void mod_destroy(void);
static int geoip2_tenant_fence_init(); 

static int w_geoip2_match(struct sip_msg* msg, char* str1, char* str2, char *str3);
static int geoip2_tenant_loc_filter(struct sip_msg* msg, char* str1, char* str2, char* str3);
static int geoip2_tenant_filter(struct sip_msg* msg, char* str1, char* str2, char* str3);
static int geoip2_match(sip_msg_t *msg, str *tomatch, str *pvclass, char* domain);
static int parse_location(geoip_tenant_info_t *tenant_info, char * str_loc); 
static int clean_cpy(char *dst, char *src, int len);

static pv_export_t mod_pvs[] = {
	{ {"gip2", sizeof("gip2")-1}, PVT_OTHER, pv_get_geoip2, 0,
		pv_parse_geoip2_name, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static cmd_export_t cmds[]={
	{"geoip2_filter", (cmd_function)geoip2_tenant_filter, 3, fixup_spve_all,
		0, ANY_ROUTE},
	{"geo_fence_allow", (cmd_function)geoip2_tenant_loc_filter, 3, fixup_spve_all,
		0, ANY_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[]={
	{"path",     PARAM_STRING, &geoip2_path},
	{"tenant_table_path", PARAM_STRING, &geoip2_tenant_table_path},
	{0, 0, 0}
};

struct module_exports exports = {
	"geoip2",			/* module name */
	DEFAULT_DLFLAGS,	/* dlopen flags */
	cmds,				/* exported functions */
	params,				/* exported parameters */
	0,					/* RPC method exports */
	mod_pvs,			/* exported pseudo-variables */
	0,					/* response handling function */
	mod_init,			/* module initialization function */
	0,					/* per-child init function */
	mod_destroy			/* module destroy function */
};

static unsigned long djb2_hash(char* str) {
    unsigned long hash = 5381;
    int c;
    while (c = *str++) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash & (MAX_TENANT_ENTRIES - 1);
}

/**
 * init module function
 */
static int mod_init(void)
{

	if(geoip2_path==NULL || strlen(geoip2_path)==0)
	{
		LM_ERR("path to GeoIP database file not set\n");
		return -1;
	}

	if(geoip2_init_pv(geoip2_path)!=0)
	{
		LM_ERR("cannot init for database file at: %s\n", geoip2_path);
		return -1;
	}
        
        if (geoip2_tenant_fence_init() <= 0) {
                return -1;
        }
        
	return 0;
}

/**
 * destroy module function
 */
static void mod_destroy(void)
{
	geoip2_destroy_pv();
}

static int clean_cpy(char *dst, char *src, int len) {
     char *tmp = src;
     while(isspace((unsigned char)*tmp)) {
       tmp++;
       len--;
     }
     while(isspace((unsigned char)tmp[len-1])) {
       len--;
     }
     memcpy(dst, tmp, len);
     dst[len] = '\0';
 
     return 0;
}

static int parse_location(geoip_tenant_info_t *tenant_info, char * str_loc) 
{
    int index = 0;
    int begin = 0;
    int count = 0;
    char *str = str_loc;

    while (str[index] != '\0') {
        if (str[index] == ',') {
            tenant_info->locs[count] = (char *)pkg_malloc(STR_LOCATION_LEN);
            clean_cpy(tenant_info->locs[count], &str[begin], index - begin);
            count++;
            index++;
            begin = index;
        }
        index++;
    }
    tenant_info->locs[count] = (char *)pkg_malloc(STR_LOCATION_LEN);
    clean_cpy(tenant_info->locs[count], &str[begin], index - begin);
    count++;
    tenant_info->loc_count = count;

    /*
    for(index=0; index<tenant_info->loc_count; index++) {
        LM_INFO("Tenant Info entry %s %s \n", tenant_info->realm, tenant_info->locs[index]);
    }
    */

    return 0;
}

/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
/*::  Function prototypes                                           :*/
/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
static double deg2rad(double);
static double rad2deg(double);
static double geo_distance(double lat1, double lon1, double lat2, double lon2, char unit);

static double geo_distance(double lat1, double lon1, double lat2, double lon2, char unit) {
  double theta, dist;
  if ((lat1 == lat2) && (lon1 == lon2)) {
    return 0;
  }
  else {
    theta = lon1 - lon2;
    dist = sin(deg2rad(lat1)) * sin(deg2rad(lat2)) + cos(deg2rad(lat1)) * cos(deg2rad(lat2)) * cos(deg2rad(theta));
    dist = acos(dist);
    dist = rad2deg(dist);
    dist = dist * 60 * 1.1515;
    switch(unit) {
      case 'M':
        break;
      case 'K':
        dist = dist * 1.609344;
        break;
      case 'N':
        dist = dist * 0.8684;
        break;
    }
    return (dist);
  }
}

/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
/*::  This function converts decimal degrees to radians             :*/
/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
static double deg2rad(double deg) {
  return (deg * pi / 180);
}

/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
/*::  This function converts radians to decimal degrees             :*/
/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
static double rad2deg(double rad) {
  return (rad * 180 / pi);
}


/*
 * Initialze tenant fencing based on location.
 */
static int geoip2_tenant_fence_init() 
{
        unsigned int hash;
        unsigned int slot;
        double radius;
        char line[256];
        char realm[120];
        char location[120];
        FILE *fp = NULL;
        geoip_tenant_info_t *record = NULL;
        char type;

        if (geoip2_tenant_table_path == NULL || strlen(geoip2_tenant_table_path) == 0)
        {
	     LM_INFO("Path to Tenant Location table not set, Feature not enabled \n");
             return 1;
        }
        
        g_tenant_tbl = (geoip_tenant_tbl_t *)pkg_malloc(sizeof(geoip_tenant_tbl_t));
        if (g_tenant_tbl == NULL) {
            LM_ERR("GeoIP fence table init failed. \n");
            return -1;
        }
        memset(g_tenant_tbl, 0, sizeof(geoip_tenant_tbl_t));
        g_tenant_tbl->entries = (geoip_tenant_info_t *)pkg_malloc(sizeof(geoip_tenant_info_t) * MAX_TENANT_ENTRIES);
        if (g_tenant_tbl->entries == NULL) {
            LM_ERR("GeoIP fence table entries init failed. \n");
            return -1;
        }
        memset(g_tenant_tbl->entries, 0, sizeof(geoip_tenant_info_t) * MAX_TENANT_ENTRIES);

        /* load whitelisted domains from db(flat file) */
        fp = fopen(geoip2_tenant_table_path, "r");
        if (!fp) {
            LM_ERR("GeoIP Failed in loading Tenant location database \n");
            return -1;
        }

        memset(line, 0, sizeof(line));
        memset(realm, 0, sizeof(realm));
        memset(location, 0, sizeof(location));
        while (fgets(line, sizeof(line), fp)) {
            if (*line == '#') {
                continue; 
            }
            sscanf(line, "%s %lf %c %[^\n]s", realm, &radius, &type, location);
            hash = djb2_hash(realm);
            slot = geoip_tenant_tbl_index(hash);
            LM_INFO("GeoIP Init slot: %s %d \n", realm, slot);
            record = &g_tenant_tbl->entries[slot];
            record->range = radius;
            record->type = type;
            strncpy(record->realm, realm, sizeof(record->realm));
            // strncpy(record->loc, location, sizeof(record->loc));
            parse_location(record, location);
            g_tenant_tbl->num_entries++;
        } 

        return 1;
} 

static int geoip2_match(sip_msg_t *msg, str *tomatch, str *pvclass, char* domain)
{

	geoip2_pv_reset(pvclass);


	return geoip2_update_pv(tomatch, pvclass);
}

static int w_geoip2_match(sip_msg_t* msg, char* target, char* pvname, char* domain)
{
	str tomatch = STR_NULL;
	str pvclass = STR_NULL;
        // LM_INFO("Enter GeoIP Target: %s PvNam: %s \n", target, pvname);

	if(msg==NULL) {
		LM_ERR("received null msg\n");
		return -1;
	}

	if(fixup_get_svalue(msg, (gparam_t*)target, &tomatch)<0) {
		LM_ERR("cannot get the address\n");
		return -1;
	}
	if(fixup_get_svalue(msg, (gparam_t*)pvname, &pvclass)<0) {
		LM_ERR("cannot get the pv class\n");
		return -1;
	}

	return geoip2_match(msg, &tomatch, &pvclass, domain);
}

static int geoip2_tenant_loc_filter(sip_msg_t* msg, char* target, char* pvname, char* domain)
{
        char realm[256];
        char src[256];
        char geo_loc[128];
        str tomatch = STR_NULL;
        str geo_hdr = STR_NULL;
        str from_domain = STR_NULL;
        geoip_data_t geoip_data;
        unsigned int hash;
        unsigned int slot;
        geoip_tenant_info_t *record = NULL;

        if (g_tenant_tbl == NULL) {
            LM_INFO("GeoIP2: Tenant Fencing feature not enabled");
            return 1;
        }

        if(msg==NULL) {
                LM_ERR("received null msg\n");
                return -1;
        }
        if(fixup_get_svalue(msg, (gparam_t*)target, &tomatch)<0) {
                LM_ERR("cannot get the address\n");
                return -1;
        }
        if(fixup_get_svalue(msg, (gparam_t*)pvname, &geo_hdr)<0) {
            LM_ERR("Failed to get X-Geo Header, drop \n");
            return -1;
        }
        if(fixup_get_svalue(msg, (gparam_t*)domain, &from_domain)<0) {
                LM_ERR("cannot get the address\n");
                return -1;
        }
        memcpy(realm, from_domain.s, from_domain.len);
        realm[from_domain.len] = '\0';
        LM_INFO("GeoIP From Domain %s %d \n", realm, from_domain.len);
        memcpy(geo_loc, geo_hdr.s, geo_hdr.len);
        geo_loc[geo_hdr.len] = '\0';
        LM_INFO("X-Geo Location %s \n", geo_loc);

        memset(src, 0, sizeof(src));
        strncpy(src, tomatch.s, tomatch.len);

        hash = djb2_hash(realm);
        slot = geoip_tenant_tbl_index(hash);
        record = &g_tenant_tbl->entries[slot];
        if (record->realm == 0 || record->loc_count == 0) {
            LM_ERR("Unknown domain - filter the message %s \n", realm);
            LM_ERR("Block traffic from %s\n", src);
            return -1;
        }

        unsigned int match = 0;
        unsigned int index = 0;

        if(geoip2_locate(&tomatch, &geoip_data)) {
            char city[256];
            char country[256];

            memset(city, 0, sizeof(city));
            memset(country, 0, sizeof(country));

            strncpy(country, geoip_data.country.s, geoip_data.country.len);
            strncpy(city, geoip_data.city.s, geoip_data.city.len);
            LM_INFO("GeoIP Location found %s %s \n", country, city);

            if (strncmp(country, GEOIP_CC_INDIA, sizeof(country))) {
                LM_ERR("Traffic from blacklisted country %s \n", country);
                LM_ERR("Block traffic from %s\n", src);
                return -1;
            }
            
            LM_INFO("Record classify %s %c \n", record->realm, record->type);
            if (record->type == 'G') {
                /*
                 * Incoming traffic
                 */
                double i_lat  = 0;
                double i_long = 0;
                sscanf(geo_loc, "%lf %lf", &i_lat, &i_long);

                LM_INFO("Incoming Geo Location %lf %lf \n", i_lat, i_long);
            
                for (index=0; index<record->loc_count; index++) {
                    double d_lat = 0;
                    double d_long = 0;
                    sscanf(record->locs[index], "%lf %lf", &d_lat, &d_long);
                    LM_INFO("Tenant Geo Location  %lf %lf \n", d_lat, d_long);

                    double result = geo_distance(i_lat, i_long, d_lat, d_long, 'K');
                    LM_INFO("Distance from the tenant location %lf \n", result);
                    if (result < record->range) {
                        LM_INFO("Allow Incoming traffic allowed range(%lf) %lf Kms \n", record->range, result);
                        match = 1;
                        break;
                    }
                }

            } else {
                for (index=0; index<record->loc_count; index++) {
                    if (!strcmp(record->locs[index], city)) {
                        LM_INFO("Allow traffic from %s for %s \n ", city, realm);
                        match = 1;
                    }
                }

            }

            if(!match) {
                LM_ERR("SIP Request from outside the tenant circle from(%s) \n", city);
                return -1;
            }
        } else {
            return -1;
        }
        return 1;
}

static int geoip2_tenant_filter(sip_msg_t* msg, char* target, char* pvname, char* domain)
{
        char realm[256];
        str tomatch = STR_NULL;
        str from_domain = STR_NULL;
        geoip_data_t geoip_data;
        unsigned int hash;
        unsigned int slot;
        geoip_tenant_info_t *record = NULL;

        if (g_tenant_tbl == NULL) {
            LM_INFO("GeoIP2: Tenant Fencing feature not enabled");
            return 1;
        }

        if(msg==NULL) {
                LM_ERR("received null msg\n");
                return -1;
        }
        if(fixup_get_svalue(msg, (gparam_t*)target, &tomatch)<0) {
                LM_ERR("cannot get the address\n");
                return -1;
        }
        if(fixup_get_svalue(msg, (gparam_t*)domain, &from_domain)<0) {
                LM_ERR("cannot get the address\n");
                return -1;
        }
        memcpy(realm, from_domain.s, from_domain.len);
        realm[from_domain.len] = '\0';
        LM_INFO("GeoIP From Domain %s %d \n", realm, from_domain.len);

        hash = djb2_hash(realm);
        slot = geoip_tenant_tbl_index(hash);
        record = &g_tenant_tbl->entries[slot];
        if (record->realm == 0 || record->loc_count == 0) {
            LM_ERR("Unknown domain - filter the message %s \n", realm);
            return -1;
        }

        if(geoip2_locate(&tomatch, &geoip_data)) {
            char city[256];
            char country[256];

            memset(city, 0, sizeof(city));
            memset(country, 0, sizeof(country));

            strncpy(country, geoip_data.country.s, geoip_data.country.len);
            strncpy(city, geoip_data.city.s, geoip_data.city.len);
            LM_INFO("GeoIP Location found %s %s \n", country, city);

            if (strncmp(country, GEOIP_CC_INDIA, sizeof(country))) {
                char src[256];

                memset(src, 0, sizeof(src));
                strncpy(src, tomatch.s, tomatch.len);
                LM_ERR("Traffic from blacklisted country %s \n", country);
                LM_ERR("Block traffic from %s\n", src);
                return -1;
            }
        } else {
            return -1;
        }

        return 1;
}

/**
 *
 */
/* clang-format off */
static sr_kemi_t sr_kemi_geoip2_exports[] = {
    { str_init("geoip2"), str_init("match"),
        SR_KEMIP_INT, geoip2_match,
        { SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_STR,
            SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
    },

    { {0, 0}, {0, 0}, 0, NULL, { 0, 0, 0, 0, 0, 0 } }
};
/* clang-format on */

int mod_register(char *path, int *dlflags, void *p1, void *p2) {
    sr_kemi_modules_add(sr_kemi_geoip2_exports);
    return 0;
}
