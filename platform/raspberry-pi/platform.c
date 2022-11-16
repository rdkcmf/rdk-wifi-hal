#include <stddef.h>
#include "wifi_hal.h"

int platform_preinit()
{
    return 0;
}

int platform_postinit(wifi_vap_info_map_t *vap_map)
{
    return 0;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    return 0;
}

int platform_get_country_code_default(char *code)
{
    return 0;
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    return 0;
}
