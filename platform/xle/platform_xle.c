#include <stddef.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"

#define BUFFER_LENGTH_WIFIDB 256

extern char *wlcsm_nvram_get(char *name);

int platform_pre_init()
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int nvram_get_default_password(char *l_password, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    int len;
    char *key_passphrase;

    memset(interface_name, 0, sizeof(interface_name));
    get_interface_name_from_vap_index(vap_index, interface_name);
    snprintf(nvram_name, sizeof(nvram_name), "%s_wpa_psk", interface_name);
    key_passphrase = wlcsm_nvram_get(nvram_name);
    if (key_passphrase == NULL) {
        wifi_hal_error_print("%s:%d nvram key_passphrase value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    len = strlen(key_passphrase);
    if (len < 8 || len > 63) {
        wifi_hal_error_print("%s:%d invalid wpa passphrase length [%d], expected length is [8..63]\r\n", __func__, __LINE__, len);
        return -1;
    }
    strcpy(l_password, key_passphrase);
    wifi_hal_dbg_print("%s:%d vap[%d] security password:%s nvram name:%s\r\n", __func__, __LINE__, vap_index, l_password, nvram_name);
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    if(is_wifi_hal_vap_mesh_sta(vap_index)) {
        return nvram_get_default_password(password, vap_index);
    }else {
        strncpy(password,"123456789",strlen("123456789")+1);
        return 0;
    }
    return -1;
}

int platform_get_ssid_default(char *ssid, int vap_index){
    char *str = NULL;
//    char value[BUFFER_LENGTH_WIFIDB] = {0};
//    FILE *fp = NULL;

    if(is_wifi_hal_vap_private(vap_index)) {
        strcpy(ssid, "OneWifi-XLE"); /* remove this and read the factory defaults below */
        return 0;
#if 0
        fp = popen("grep \"Default 2.4 GHz SSID:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");

        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
                strncpy(ssid,value,strlen(value)-1);
            }
            pclose(fp);
            return 0;
        }
#endif
    }else if(is_wifi_hal_vap_xhs(vap_index)) {
        strcpy(ssid, "OneWifi-XLE"); /* remove this and read the factory defaults below */
        return 0;
#if 0
        fp = popen("grep \"Default XHS SSID for 2.4GHZ and 5.0GHZ:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");

        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
                strncpy(ssid,value,strlen(value)-1);
            }
            pclose(fp);
            return 0;
        }
#endif
    }else if(is_wifi_hal_vap_lnf_psk(vap_index)) {
        str = "A16746DF2466410CA2ED9FB2E32FE7D9";
        strncpy(ssid,str,strlen(str)+1);
        return 0;
    }else if(is_wifi_hal_vap_lnf_radius(vap_index)) {
        str = "D375C1D9F8B041E2A1995B784064977B";
        strncpy(ssid,str,strlen(str)+1);
        return 0;
    }else if(is_wifi_hal_vap_mesh_backhaul(vap_index)){
        str = "we.piranha.off";
        strncpy(ssid,str,strlen(str)+1);
        return 0;
    }else if(is_wifi_hal_vap_mesh_sta(vap_index)) {
        str = "we.connect.yellowstone";
        strncpy(ssid,str,strlen(str)+1);
        return 0;
    }else {
        str = "OutOfService";
        strncpy(ssid,str,strlen(str)+1);
        return 0;
    }
    return -1;
}

int platform_get_wps_pin_default(char *pin)
{
    strcpy(pin, "88626277"); /* remove this and read the factory defaults below */
    wifi_hal_dbg_print("%s default wps pin:%s\n", __func__, pin);
    return 0;
#if 0
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;
    fp = popen("grep \"Default WPS Pin:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
    if(fp != NULL) {
        while (fgets(value, sizeof(value), fp) != NULL) {
            strncpy(pin, value, strlen(value) - 1);
        }
        pclose(fp);
        return 0;
    }
    return -1;
#endif
}
int platform_get_country_code_default(char *code)
{
    return 0;
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    return nvram_get_default_password(l_password, vap_index);
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    int len;
    char *ssid;

    memset(interface_name, 0, sizeof(interface_name));
    get_interface_name_from_vap_index(vap_index, interface_name);
    snprintf(nvram_name, sizeof(nvram_name), "%s_ssid", interface_name);
    ssid = wlcsm_nvram_get(nvram_name);
    if (ssid == NULL) {
        wifi_hal_error_print("%s:%d nvram ssid value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    len = strlen(ssid);
    if (len < 0 || len > 63) {
        wifi_hal_error_print("%s:%d invalid ssid length [%d], expected length is [0..63]\r\n", __func__, __LINE__, len);
        return -1;
    }
    strcpy(l_ssid, ssid);
    wifi_hal_dbg_print("%s:%d vap[%d] ssid:%s nvram name:%s\r\n", __func__, __LINE__, vap_index, l_ssid, nvram_name);
    return 0;
}
