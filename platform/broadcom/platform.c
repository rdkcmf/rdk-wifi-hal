#include <stddef.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "wlcsm_lib_api.h"

#define BUFFER_LENGTH_WIFIDB 256

int sta_disassociated(int ap_index, char *mac, int reason);
int sta_deauthenticated(int ap_index, char *mac, int reason);
int sta_associated(int ap_index, wifi_associated_dev_t *associated_dev);

int sta_disassociated(int ap_index, char *mac, int reason)
{
    return 0;
}

int sta_deauthenticated(int ap_index, char *mac, int reason)
{
    return 0;
}

int sta_associated(int ap_index, wifi_associated_dev_t *associated_dev)
{
    return 0;
}

void prepare_param_name(char *dest, char *interface_name, char *prefix)
{
    memset(dest, 0, strlen(dest));

    strncpy(dest, interface_name, strlen(interface_name));
    strcat(dest, prefix);
}

void set_decimal_nvram_param(char *param_name, unsigned int value)
{
    char temp_buff[8];
    memset(temp_buff, 0 ,sizeof(temp_buff));

    snprintf(temp_buff, sizeof(temp_buff), "%d", value);
    wlcsm_nvram_set(param_name, temp_buff);
}

void set_string_nvram_param(char *param_name, char *value)
{
    wlcsm_nvram_set(param_name, value);
}

int platform_pre_init()
{
    wifi_hal_dbg_print("%s:%d \r\n", __func__, __LINE__);

//    wlcsm_nvram_set("wl0_bw_cap", "3");
    /* registering the dummy callbacks to receive the events in plume */
    wifi_newApAssociatedDevice_callback_register(sta_associated);
    wifi_apDeAuthEvent_callback_register(sta_deauthenticated);
    wifi_apDisassociatedDevice_callback_register(sta_disassociated);
#if 0
    system("wl -i wl0.1 nmode_protection_override 0");
    system("wl -i wl1.1 nmode_protection_override 0");
    system("wl -i wl0.1 protection_control 0");
    system("wl -i wl1.1 protection_control 0");
    system("wl -i wl0.1 gmode_protection_control 0");
    system("wl -i wl1.1 gmode_protection_control 0");
    wifi_hal_dbg_print("%s:%d: wifi param set success\r\n", __func__, __LINE__);
#endif
    return 0;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    if ((index < 0) || (operationParam == NULL)) {
        wifi_hal_dbg_print("%s:%d Invalid Argument \n", __FUNCTION__, __LINE__);
        return -1;
    }

    char temp_buff[BUF_SIZE];
    char param_name[NVRAM_NAME_SIZE];
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }
    
    if (radio->oper_param.countryCode != operationParam->countryCode) {
        memset(temp_buff, 0 ,sizeof(temp_buff));
        get_coutry_str_from_code(operationParam->countryCode, temp_buff);
        if (wifi_setRadioCountryCode(index, temp_buff) != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d Failure in setting country code as %s in radio index %d\n", __FUNCTION__, __LINE__, temp_buff, index);
            return -1;
        }

        if (wifi_applyRadioSettings(index) != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d Failure in applying Radio settings in radio index %d\n", __FUNCTION__, __LINE__, index);
            return -1;
        }

        //Updating nvram param
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_country_code", index);
        set_string_nvram_param(param_name, temp_buff);
    }

    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    int i, index;
    char param_name[NVRAM_NAME_SIZE];
    char interface_name[8];

    memset(param_name, 0 ,sizeof(param_name));
    memset(interface_name, 0, sizeof(interface_name));

    wifi_hal_dbg_print("%s:%d: start_security_apps\n", __func__, __LINE__);
    system("wifi_setup.sh start_security_apps");

    wifi_hal_dbg_print("%s:%d: add wifi interfaces to flow manager\r\n", __func__, __LINE__);
    system("wifi_setup.sh add_ifaces_to_flowmgr");

    if (system("killall -q -9 acsd2 2>/dev/null")) {
        wifi_hal_info_print("%s: system kill acsd2 failed\n", __FUNCTION__);
    }

    if (system("acsd2")) {
        wifi_hal_info_print("%s: system acsd2 failed\n", __FUNCTION__);
    }

    wlcsm_nvram_set("acsd2_started", "1");

    wifi_hal_info_print("%s:%d: acsd2_started\r\n", __func__, __LINE__);

    system("wl -i wl0.1 nmode_protection_override 0");
    system("wl -i wl1.1 nmode_protection_override 0");
    system("wl -i wl0.1 protection_control 0");
    system("wl -i wl1.1 protection_control 0");
    system("wl -i wl0.1 gmode_protection_control 0");
    system("wl -i wl1.1 gmode_protection_control 0");
    wifi_hal_dbg_print("%s:%d: wifi param set success\r\n", __func__, __LINE__);

    if (vap_map != NULL) {
        for(i = 0; i < g_wifi_hal.num_radios; i++) {
            if (vap_map != NULL) {
                for (index = 0; index < vap_map->num_vaps; index++) {
                    memset(param_name, 0 ,sizeof(param_name));
                    memset(interface_name, 0, sizeof(interface_name));
                    get_interface_name_from_vap_index(vap_map->vap_array[index].vap_index, interface_name);
                    if (vap_map->vap_array[index].vap_mode == wifi_vap_mode_ap) {
                        prepare_param_name(param_name, interface_name, "_bss_maxassoc");
                        set_decimal_nvram_param(param_name, vap_map->vap_array[index].u.bss_info.bssMaxSta);
                        wifi_hal_dbg_print("%s:%d: nvram param name:%s vap_bssMaxSta:%d\r\n", __func__, __LINE__, param_name, vap_map->vap_array[index].u.bss_info.bssMaxSta);
                    }
                }
                vap_map++;
            } else {
                wifi_hal_error_print("%s:%d: vap_map NULL for radio_index:%d\r\n", __func__, __LINE__, i);
            }
        }
    }

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
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

    if(is_wifi_hal_vap_private(vap_index)) {
#ifdef SKYSR300_PORT
        fp = popen("grep \"WIFIPASSWORD=\" /tmp/serial.txt | cut -d '=' -f 2 | tr -d '\r\n'","r");
#else
        fp = popen("grep \"Default WIFI Password:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
#endif
        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
#ifdef SKYSR300_PORT
                strncpy(password,value,strlen(value));
#else
                strncpy(password,value,strlen(value)-1);
#endif
            }
            pclose(fp);
            return 0;
        }
    } else {
        return nvram_get_default_password(password, vap_index);
    }
    return -1;
}
int platform_get_radius_key_default(char *radius_key)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char *key;

    snprintf(nvram_name, sizeof(nvram_name), "default_radius_key");
    key = wlcsm_nvram_get(nvram_name);
    if (key == NULL) {
        wifi_hal_error_print("%s:%d default_radius_key value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    else {
        strcpy(radius_key,key);
        wifi_hal_dbg_print("%s:%d::nvram name %s and radius_key %s\n",__func__, __LINE__, nvram_name,radius_key);
    }
    return 0;
}
int platform_get_ssid_default(char *ssid, int vap_index){
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

    if(is_wifi_hal_vap_private(vap_index)) {

#ifdef SKYSR300_PORT
        fp = popen("grep \"FACTORYSSID=\" /tmp/serial.txt | cut -d '=' -f2 | tr -d '\r\n'","r");
#else
        fp = popen("grep \"Default 2.4 GHz SSID:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
#endif

        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
#ifdef SKYSR300_PORT
                strncpy(ssid,value,strlen(value));
#else
                strncpy(ssid,value,strlen(value)-1);
#endif
            }
            pclose(fp);
            return 0;
        }
    }else if(is_wifi_hal_vap_xhs(vap_index)) {
        fp = popen("grep \"Default XHS SSID for 2.4GHZ and 5.0GHZ:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");

        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
                strncpy(ssid,value,strlen(value)-1);
            }
            pclose(fp);
            return 0;
        }
    }
    else {
        return nvram_get_current_ssid(ssid, vap_index);
    }
    return -1;
}

int platform_get_wps_pin_default(char *pin)
{
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;
#ifdef SKYSR300_PORT
    fp = popen("grep \"WPSPIN=\" /tmp/serial.txt | cut -d '=' -f2 | tr -d '\r\n'","r");
#else
    fp = popen("grep \"Default WPS Pin:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
#endif
    if(fp != NULL) {
        while (fgets(value, sizeof(value), fp) != NULL) {
#ifdef SKYSR300_PORT
            strncpy(pin,value,strlen(value));
#else
            strncpy(pin,value,strlen(value)-1);
#endif
        }
        pclose(fp);
        return 0;
    }
    return -1;
}

int platform_wps_event(wifi_wps_event_t data)
{
    switch(data.event) {
        case WPS_EV_PBC_ACTIVE:
            // set wps led color to blue
            system("led_wps_active 1");
            wifi_hal_dbg_print("%s:%d set wps led color to blue\r\n", __func__, __LINE__);
            break;

        case WPS_EV_SUCCESS:
        case WPS_EV_PBC_TIMEOUT:
            // set wps led color to white
            system("led_wps_active 0");
            wifi_hal_dbg_print("%s:%d set wps led color to white\r\n", __func__, __LINE__);
            break;

        default:
            wifi_hal_info_print("%s:%d wps event[%d] not handle\r\n", __func__, __LINE__, data.event);
            break;
    }

    return 0;
}

int platform_get_country_code_default(char *code)
{
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

    fp = popen("cat /data/.customerId", "r");

    if (fp != NULL) {
        while(fgets(value, sizeof(value), fp) != NULL) {
            strncpy(code, value, strlen(value)-1);
        }
        pclose(fp);
        return 0;
    }
    return -1;
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

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    
    char temp_buff[BUF_SIZE];
    char param_name[NVRAM_NAME_SIZE];
    memset(param_name, 0 ,sizeof(param_name));
    memset(temp_buff, 0 ,sizeof(temp_buff));
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, index);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_auto_cha", index);
    set_decimal_nvram_param(param_name, operationParam->autoChannelEnabled);

    if (operationParam->autoChannelEnabled) {
        set_string_nvram_param("acsd_restart", "yes");
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_channel", index);
        set_decimal_nvram_param(param_name, 0);

        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_chanspec", index);
        set_decimal_nvram_param(param_name, 0);
    } else {
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_channel", index);
        set_decimal_nvram_param(param_name, operationParam->channel);
    }

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_dtim", index);
    set_decimal_nvram_param(param_name, operationParam->dtimPeriod);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_frag", index);
    set_decimal_nvram_param(param_name, operationParam->fragmentationThreshold);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_nband", index);
    set_decimal_nvram_param(param_name, operationParam->band);

    memset(param_name, 0 ,sizeof(param_name));
    memset(temp_buff, 0 ,sizeof(temp_buff));
    sprintf(param_name, "wl%d_oper_stands", index);
    get_radio_variant_str_from_int(operationParam->variant, temp_buff);
    set_string_nvram_param(param_name, temp_buff);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_bcn", index);
    set_decimal_nvram_param(param_name, operationParam->beaconInterval);

    return 0;
}

int platform_create_vap(wifi_radio_index_t r_index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, r_index);
    int  index = 0;
    char temp_buff[256];
    char param_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    wifi_radio_info_t *radio;
    char das_ipaddr[45];
    wifi_interface_info_t *interface;
    memset(temp_buff, 0 ,sizeof(temp_buff));
    memset(param_name, 0 ,sizeof(param_name));
    memset(interface_name, 0, sizeof(interface_name));

    for (index = 0; index < map->num_vaps; index++) {

        radio = get_radio_by_rdk_index(r_index);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, r_index);
            return RETURN_ERR;
        }

        interface = get_interface_by_vap_index(map->vap_array[index].vap_index);

        memset(interface_name, 0, sizeof(interface_name));
        get_interface_name_from_vap_index(map->vap_array[index].vap_index, interface_name);

        prepare_param_name(param_name, interface_name, "_ifname");
        set_string_nvram_param(param_name, interface_name);

        memset(temp_buff, 0 ,sizeof(temp_buff));
        prepare_param_name(param_name, interface_name, "_mode");
        get_vap_mode_str_from_int_mode(map->vap_array[index].vap_mode, temp_buff);
        set_string_nvram_param(param_name, temp_buff);

        prepare_param_name(param_name, interface_name, "_radio");
        set_decimal_nvram_param(param_name, 1);

        prepare_param_name(param_name, interface_name, "_reg_mode");
        if (radio->iconf.ieee80211h != 0) {
            set_string_nvram_param(param_name, "h");
        } else {
            set_decimal_nvram_param(param_name, radio->iconf.ieee80211h);
        }

        if (map->vap_array[index].vap_mode == wifi_vap_mode_ap) {

            prepare_param_name(param_name, interface_name, "_akm");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_mode_str_from_int(map->vap_array[index].u.bss_info.security.mode, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_crypto");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_encryption_mode_str_from_int(map->vap_array[index].u.bss_info.security.encr, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_mfp");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.mfp);

            prepare_param_name(param_name, interface_name, "_ap_isolate");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.isolation);

            prepare_param_name(param_name, interface_name, "_closed");
            set_decimal_nvram_param(param_name, interface->u.ap.conf.ignore_broadcast_ssid);

            prepare_param_name(param_name, interface_name, "_bss_maxassoc");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.bssMaxSta);

            prepare_param_name(param_name, interface_name, "_ssid");
            set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.ssid);

            memset(temp_buff, 0 ,sizeof(temp_buff));
            prepare_param_name(param_name, interface_name, "_wps_mode");
            if (map->vap_array[index].u.bss_info.wps.enable) {
                strcpy(temp_buff, "enabled");
            } else {
                strcpy(temp_buff, "disabled");
            }
            set_string_nvram_param(param_name, temp_buff);

            prepare_param_name(param_name, interface_name, "_wps_device_pin");
            set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.wps.pin);

            memset(temp_buff, 0 ,sizeof(temp_buff));
            prepare_param_name(param_name, interface_name, "_wps_method_enabled");
            wps_enum_to_string(map->vap_array[index].u.bss_info.wps.methods, temp_buff, sizeof(temp_buff));
            set_string_nvram_param(param_name, temp_buff);

            prepare_param_name(param_name, interface_name, "_wps_config_state");
            set_decimal_nvram_param(param_name, interface->u.ap.conf.wps_state);

            if ((get_security_mode_support_radius(map->vap_array[index].u.bss_info.security.mode))|| is_wifi_hal_vap_hotspot_open(map->vap_array[index].vap_index)) {

                prepare_param_name(param_name, interface_name, "_radius_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.port);

                prepare_param_name(param_name, interface_name, "_radius_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.ip);

                prepare_param_name(param_name, interface_name, "_radius_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.key);

                prepare_param_name(param_name, interface_name, "_radius2_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.s_port);

                prepare_param_name(param_name, interface_name, "_radius2_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.s_ip);

                prepare_param_name(param_name, interface_name, "_radius2_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.s_key);

                memset(&das_ipaddr, 0, sizeof(das_ipaddr));
                getIpStringFromAdrress(das_ipaddr,&map->vap_array[index].u.bss_info.security.u.radius.dasip);

                prepare_param_name(param_name, interface_name, "_radius_das_client_ipaddr");
                set_string_nvram_param(param_name, das_ipaddr);

                prepare_param_name(param_name, interface_name, "_radius_das_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.daskey);

                prepare_param_name(param_name, interface_name, "_radius_das_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.dasport);
            } else {
                prepare_param_name(param_name, interface_name, "_wpa_psk");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.key.key);
            }

            prepare_param_name(param_name, interface_name, "_hessid");
            set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.interworking.interworking.hessid);

            prepare_param_name(param_name, interface_name, "_venuegrp");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.interworking.interworking.venueGroup);

            prepare_param_name(param_name, interface_name, "_venuetype");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.interworking.interworking.venueType);

        } else if (map->vap_array[index].vap_mode == wifi_vap_mode_sta) {

            prepare_param_name(param_name, interface_name, "_akm");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_mode_str_from_int(map->vap_array[index].u.sta_info.security.mode, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_crypto");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_encryption_mode_str_from_int(map->vap_array[index].u.sta_info.security.encr, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_mfp");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.mfp);

            prepare_param_name(param_name, interface_name, "_ssid");
            set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.ssid);


            if ((get_security_mode_support_radius(map->vap_array[index].u.sta_info.security.mode))|| is_wifi_hal_vap_hotspot_open(map->vap_array[index].vap_index)) {

                prepare_param_name(param_name, interface_name, "_radius_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.port);

                prepare_param_name(param_name, interface_name, "_radius_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.ip);

                prepare_param_name(param_name, interface_name, "_radius_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.key);

                prepare_param_name(param_name, interface_name, "_radius2_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.s_port);

                prepare_param_name(param_name, interface_name, "_radius2_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.s_ip);

                prepare_param_name(param_name, interface_name, "_radius2_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.s_key);

                memset(&das_ipaddr, 0, sizeof(das_ipaddr));
                getIpStringFromAdrress(das_ipaddr,&map->vap_array[index].u.sta_info.security.u.radius.dasip);

                prepare_param_name(param_name, interface_name, "_radius_das_client_ipaddr");
                set_string_nvram_param(param_name, das_ipaddr);

                prepare_param_name(param_name, interface_name, "_radius_das_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.daskey);

                prepare_param_name(param_name, interface_name, "_radius_das_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.dasport);

            } else {
                prepare_param_name(param_name, interface_name, "_wpa_psk");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.key.key);
            }
        }
    }

    return 0;
}

