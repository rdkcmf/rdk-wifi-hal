/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <linux/nl80211.h>

wifi_interface_name_idex_map_t interface_index_map[] = {
#ifdef RASPBERRY_PI_PORT
    {1, 0,  "wlan1",   "brlan1",    0,    true,   14,     "mesh_sta_2g"},
    {2, 1,  "wlan2",   "brlan0",    0,    true,   0,      "private_ssid_2g"},
    {3, 2,  "wlan3",   "brlan112",  0,    true,   12,      "mesh_backhaul_2g"},
#endif

#ifdef TCXB7_PORT // for Broadcom based platforms
    {0, 0,  "wl0.1",   "brlan0",  100,    false,  0,      "private_ssid_2g"},
    {1, 1,  "wl1.1",   "brlan0",  100,    false,  1,      "private_ssid_5g"},
    {0, 0,  "wl0.2",   "brlan1",  101,    false,  2,      "iot_ssid_2g"},
    {1, 1,  "wl1.2",   "brlan1",  101,    false,  3,      "iot_ssid_5g"},
    {0, 0,  "wl0.3",   "brlan2",  102,    false,  4,      "hotspot_open_2g"},
    {1, 1,  "wl1.3",   "brlan3",  103,    false,  5,      "hotspot_open_5g"},
    {0, 0,  "wl0.4",   "br106",   106,    false,  6,      "lnf_psk_2g"},
    {1, 1,  "wl1.4",   "br106",   106,    false,  7,      "lnf_psk_5g"},
    {0, 0,  "wl0.5",   "brlan4",  104,    false,  8,      "hotspot_secure_2g"},
    {1, 1,  "wl1.5",   "brlan5",  105,    false,  9,      "hotspot_secure_5g"},
    {0, 0,  "wl0.6",   "br106",   106,    false,  10,     "lnf_radius_2g"},
    {1, 1,  "wl1.6",   "br106",   106,    false,  11,     "lnf_radius_5g"},
    {0, 0,  "wl0.7",   "brlan112",  0,    false,  12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1.7",   "brlan113",  0,    false,  13,     "mesh_backhaul_5g"},
    {0, 0,  "wl0",     "brlan1",    0,    true,   14,     "mesh_sta_2g"},
    {1, 1,  "wl1",     "brlan1",    0,    true,   15,     "mesh_sta_5g"},
#endif

#ifdef XLE_PORT // for Broadcom XLE
#ifdef XLE_3_RADIO_SUPPORT
    {0, 0,  "wl0",     "",          0,    true,   14,     "mesh_sta_2g"},
    {0, 0,  "wl0.1",   "brlan0",  100,    false,  0,      "private_ssid_2g"},
    {0, 0,  "wl0.2",   "brlan1",  101,    false,  2,      "iot_ssid_2g"},
    {0, 0,  "wl0.3",   "brlan2",  102,    false,  4,      "hotspot_open_2g"},
    {0, 0,  "wl0.4",   "br106",   106,    false,  6,      "lnf_psk_2g"},
    {0, 0,  "wl0.5",   "brlan4",  104,    false,  8,      "hotspot_secure_2g"},
    {0, 0,  "wl0.6",   "br106",   106,    false,  10,     "lnf_radius_2g"},
    {0, 0,  "wl0.7",   "brlan112",112,    false,  12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1",     "",          0,    true,   15,     "mesh_sta_5gl"},
    {1, 1,  "wl1.1",   "brlan0",  100,    false,  1,      "private_ssid_5gl"},
    {1, 1,  "wl1.2",   "brlan1",  101,    false,  3,      "iot_ssid_5gl"},
    {1, 1,  "wl1.3",   "brlan3",  103,    false,  5,      "hotspot_open_5gl"},
    {1, 1,  "wl1.4",   "br106",   106,    false,  7,      "lnf_psk_5gl"},
    {1, 1,  "wl1.5",   "brlan5",  105,    false,  9,      "hotspot_secure_5gl"},
    {1, 1,  "wl1.6",   "br106",   106,    false,  11,     "lnf_radius_5gl"},
    {1, 1,  "wl1.7",   "brlan113",113,    false,  13,     "mesh_backhaul_5gl"},
    {2, 2,  "wl2",     "",          0,    true,   23,     "mesh_sta_5gh"},
    {2, 2,  "wl2.1",   "brlan0",  100,    false,  16,     "private_ssid_5gh"},
    {2, 2,  "wl2.2",   "brlan1",  101,    false,  17,     "iot_ssid_5gh"},
    {2, 2,  "wl2.3",   "brlan3",  103,    false,  18,     "hotspot_open_5gh"},
    {2, 2,  "wl2.4",   "br106",   106,    false,  19,     "lnf_psk_5gh"},
    {2, 2,  "wl2.5",   "brlan5",  105,    false,  20,     "hotspot_secure_5gh"},
    {2, 2,  "wl2.6",   "br106",   106,    false,  21,     "lnf_radius_5gh"},
    {2, 2,  "wl2.7",   "brlan113",114,    false,  22,     "mesh_backhaul_5gh"},
#else
    {0, 0,  "wl0",     "",          0,    true,   14,     "mesh_sta_2g"},
    {0, 0,  "wl0.1",   "brlan0",  100,    false,  0,      "private_ssid_2g"},
    {0, 0,  "wl0.2",   "brlan1",  101,    false,  2,      "iot_ssid_2g"},
    {0, 0,  "wl0.3",   "brlan2",  102,    false,  4,      "hotspot_open_2g"},
    {0, 0,  "wl0.4",   "br106",   106,    false,  6,      "lnf_psk_2g"},
    {0, 0,  "wl0.5",   "brlan4",  104,    false,  8,      "hotspot_secure_2g"},
    {0, 0,  "wl0.6",   "br106",   106,    false,  10,     "lnf_radius_2g"},
    {0, 0,  "wl0.7",   "brlan112",112,    false,  12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1",     "",          0,    true,   15,     "mesh_sta_5g"},
    {1, 1,  "wl1.1",   "brlan0",  100,    false,  1,      "private_ssid_5g"},
    {1, 1,  "wl1.2",   "brlan1",  101,    false,  3,      "iot_ssid_5g"},
    {1, 1,  "wl1.3",   "brlan3",  103,    false,  5,      "hotspot_open_5g"},
    {1, 1,  "wl1.4",   "br106",   106,    false,  7,      "lnf_psk_5g"},
    {1, 1,  "wl1.5",   "brlan5",  105,    false,  9,      "hotspot_secure_5g"},
    {1, 1,  "wl1.6",   "br106",   106,    false,  11,     "lnf_radius_5g"},
    {1, 1,  "wl1.7",   "brlan113",113,    false,  13,     "mesh_backhaul_5g"},
#endif
#endif

#ifdef TCXB8_PORT
    {1, 0,  "wl0",     "",         0,     true,   14,     "mesh_sta_2g"},
    {1, 0,  "wl0.1",   "brlan0",   100,   false,  0,      "private_ssid_2g"},
    {1, 0,  "wl0.2",   "brlan1",   101,   false,  2,      "iot_ssid_2g"},
    {1, 0,  "wl0.3",   "brlan2",   102,   false,  4,      "hotspot_open_2g"},
    {1, 0,  "wl0.4",   "br106",    106,   false,  6,      "lnf_psk_2g"},
    {1, 0,  "wl0.5",   "brlan4",   104,   false,  8,      "hotspot_secure_2g"},
    {1, 0,  "wl0.6",   "br106",    106,   false,  10,     "lnf_radius_2g"},
    {1, 0,  "wl0.7",   "brlan112", 112,   false,  12,     "mesh_backhaul_2g"},
    {0, 1,  "wl1",     "",         0,     true,   15,     "mesh_sta_5g"},
    {0, 1,  "wl1.1",   "brlan0",   100,   false,  1,      "private_ssid_5g"},
    {0, 1,  "wl1.2",   "brlan1",   101,   false,  3,      "iot_ssid_5g"},
    {0, 1,  "wl1.3",   "brlan3",   103,   false,  5,      "hotspot_open_5g"},
    {0, 1,  "wl1.4",   "br106",    106,   false,  7,      "lnf_psk_5g"},
    {0, 1,  "wl1.5",   "brlan5",   105,   false,  9,      "hotspot_secure_5g"},
    {0, 1,  "wl1.6",   "br106",    106,   false,  11,     "lnf_radius_5g"},
    {0, 1,  "wl1.7",   "brlan113", 113,   false,  13,     "mesh_backhaul_5g"},
    {2, 2,  "wl2",     "",         0,     true,   23,     "mesh_sta_6g"},
    {2, 2,  "wl2.1",   "brlan0",   100,   false,  16,     "private_ssid_6g"},
    {2, 2,  "wl2.4",   "brlan6",   106,   false,  19,     "lnf_psk_6g"},
    {2, 2,  "wl2.7",   "brlan113", 0,     false,  22,     "mesh_backhaul_6g"},
#endif

    // for Intel based platforms
};

static char const *bss_nvifname[] = {
    "wl0",      "wl1",
    "wl0.1",    "wl1.1",
    "wl0.2",    "wl1.2",
    "wl0.3",    "wl1.3",
    "wl0.4",    "wl1.4",
    "wl0.5",    "wl1.5",
    "wl0.6",    "wl1.6",
    "wl0.7",    "wl1.7",
    "wl2",      "wl2.1",
    "wl2.2",    "wl2.3",
    "wl2.4",    "wl2.5",
    "wl2.6",    "wl2.7",
};  /* Indexed by apIndex */

const wifi_driver_info_t  driver_info = {
#ifdef RASPBERRY_PI_PORT
    "pi4",
    "cfg80211",
    {"RaspBerry","RaspBerry","PI","PI","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default
#endif

#ifdef TCXB7_PORT // for Broadcom based platforms
    "tcxb7",
    "dhd",
    {"Xfinity Wireless Gateway","Technicolor","XB7","CGM4331COM","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default
#endif

#ifdef TCXB8_PORT // for Broadcom based platforms
    "tcxb8",
    "dhd",
    {"Xfinity Wireless Gateway","Technicolor","XB8","CGM4981COM","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default
#endif

#ifdef XLE_PORT // for Broadcom XLE
    "xle",
    "cfg80211",
    {"Xfinity Wireless Gateway","SKY","XLE","WNXL11BWL","Model Description","Model URL","267","WPS Access Point","Manufacturer URL"},
    platform_pre_init,
    platform_post_init,
    platform_set_radio,
    platform_set_radio_pre_init,
    platform_create_vap,
    platform_get_ssid_default,
    platform_get_keypassphrase_default,
    platform_get_radius_key_default,
    platform_get_wps_pin_default,
    platform_get_country_code_default
#endif
};

static struct wifiCountryEnumStrMap wifi_country_map[] =
{
    {wifi_countrycode_AC,"AC"}, /**< ASCENSION ISLAND */
    {wifi_countrycode_AD,"AD"}, /**< ANDORRA */
    {wifi_countrycode_AE,"AE"}, /**< UNITED ARAB EMIRATES */
    {wifi_countrycode_AF,"AF"}, /**< AFGHANISTAN */
    {wifi_countrycode_AG,"AG"}, /**< ANTIGUA AND BARBUDA */
    {wifi_countrycode_AI,"AI"}, /**< ANGUILLA */
    {wifi_countrycode_AL,"AL"}, /**< ALBANIA */
    {wifi_countrycode_AM,"AM"}, /**< ARMENIA */
    {wifi_countrycode_AN,"AN"}, /**< NETHERLANDS ANTILLES */
    {wifi_countrycode_AO,"AO"}, /**< ANGOLA */
    {wifi_countrycode_AQ,"AQ"}, /**< ANTARCTICA */
    {wifi_countrycode_AR,"AR"}, /**< ARGENTINA */
    {wifi_countrycode_AS,"AS"}, /**< AMERICAN SAMOA */
    {wifi_countrycode_AT,"AT"}, /**< AUSTRIA */
    {wifi_countrycode_AU,"AU"}, /**< AUSTRALIA */
    {wifi_countrycode_AW,"AW"}, /**< ARUBA */
    {wifi_countrycode_AZ,"AZ"}, /**< AZERBAIJAN */
    {wifi_countrycode_BA,"BA"}, /**< BOSNIA AND HERZEGOVINA */
    {wifi_countrycode_BB,"BB"}, /**< BARBADOS */
    {wifi_countrycode_BD,"BD"}, /**< BANGLADESH */
    {wifi_countrycode_BE,"BE"}, /**< BELGIUM */
    {wifi_countrycode_BF,"BF"}, /**< BURKINA FASO */
    {wifi_countrycode_BG,"BG"}, /**< BULGARIA */
    {wifi_countrycode_BH,"BH"}, /**< BAHRAIN */
    {wifi_countrycode_BI,"BI"}, /**< BURUNDI */
    {wifi_countrycode_BJ,"BJ"}, /**< BENIN */
    {wifi_countrycode_BM,"BM"}, /**< BERMUDA */
    {wifi_countrycode_BN,"BN"}, /**< BRUNEI DARUSSALAM */
    {wifi_countrycode_BO,"BO"}, /**< BOLIVIA */
    {wifi_countrycode_BR,"BR"}, /**< BRAZIL */
    {wifi_countrycode_BS,"BS"}, /**< BAHAMAS */
    {wifi_countrycode_BT,"BT"}, /**< BHUTAN */
    {wifi_countrycode_BV,"BV"}, /**< BOUVET ISLAND */
    {wifi_countrycode_BW,"BW"}, /**< BOTSWANA */
    {wifi_countrycode_BY,"BY"}, /**< BELARUS */
    {wifi_countrycode_BZ,"BZ"}, /**< BELIZE */
    {wifi_countrycode_CA,"CA"}, /**< CANADA */
    {wifi_countrycode_CC,"CC"}, /**< COCOS (KEELING) ISLANDS */
    {wifi_countrycode_CD,"CD"}, /**< CONGO,THE DEMOCRATIC REPUBLIC OF THE */
    {wifi_countrycode_CF,"CF"}, /**< CENTRAL AFRICAN REPUBLIC */
    {wifi_countrycode_CG,"CG"}, /**< CONGO */
    {wifi_countrycode_CH,"CH"}, /**< SWITZERLAND */
    {wifi_countrycode_CI,"CI"}, /**< COTE D'IVOIRE */
    {wifi_countrycode_CK,"CK"}, /**< COOK ISLANDS */
    {wifi_countrycode_CL,"CL"}, /**< CHILE */
    {wifi_countrycode_CM,"CM"}, /**< CAMEROON */
    {wifi_countrycode_CN,"CN"}, /**< CHINA */
    {wifi_countrycode_CO,"CO"}, /**< COLOMBIA */
    {wifi_countrycode_CP,"CP"}, /**< CLIPPERTON ISLAND */
    {wifi_countrycode_CR,"CR"}, /**< COSTA RICA */
    {wifi_countrycode_CU,"CU"}, /**< CUBA */
    {wifi_countrycode_CV,"CV"}, /**< CAPE VERDE */
    {wifi_countrycode_CY,"CY"}, /**< CYPRUS */
    {wifi_countrycode_CX,"CX"}, /**< CHRISTMAS ISLAND */
    {wifi_countrycode_CZ,"CZ"}, /**< CZECH REPUBLIC */
    {wifi_countrycode_DE,"DE"}, /**< GERMANY */
    {wifi_countrycode_DJ,"DJ"}, /**< DJIBOUTI */
    {wifi_countrycode_DK,"DK"}, /**< DENMARK */
    {wifi_countrycode_DM,"DM"}, /**< DOMINICA */
    {wifi_countrycode_DO,"DO"}, /**< DOMINICAN REPUBLIC */
    {wifi_countrycode_DZ,"DZ"}, /**< ALGERIA */
    {wifi_countrycode_EC,"EC"}, /**< ECUADOR */
    {wifi_countrycode_EE,"EE"}, /**< ESTONIA */
    {wifi_countrycode_EG,"EG"}, /**< EGYPT */
    {wifi_countrycode_EH,"EH"}, /**< WESTERN SAHARA */
    {wifi_countrycode_ER,"ER"}, /**< ERITREA */
    {wifi_countrycode_ES,"ES"}, /**< SPAIN */
    {wifi_countrycode_ET,"ET"}, /**< ETHIOPIA */
    {wifi_countrycode_FI,"FI"}, /**< FINLAND */
    {wifi_countrycode_FJ,"FJ"}, /**< FIJI */
    {wifi_countrycode_FK,"FK"}, /**< FALKLAND ISLANDS (MALVINAS) */
    {wifi_countrycode_FM,"FM"}, /**< MICRONESIA FEDERATED STATES OF */
    {wifi_countrycode_FO,"FO"}, /**< FAROE ISLANDS */
    {wifi_countrycode_FR,"FR"}, /**< FRANCE */
    {wifi_countrycode_GA,"GA"}, /**< GABON */
    {wifi_countrycode_GB,"GB"}, /**< UNITED KINGDOM */
    {wifi_countrycode_GD,"GD"}, /**< GRENADA */
    {wifi_countrycode_GE,"GE"}, /**< GEORGIA */
    {wifi_countrycode_GF,"GF"}, /**< FRENCH GUIANA */
    {wifi_countrycode_GG,"GG"}, /**< GUERNSEY */
    {wifi_countrycode_GH,"GH"}, /**< GHANA */
    {wifi_countrycode_GI,"GI"}, /**< GIBRALTAR */
    {wifi_countrycode_GL,"GL"}, /**< GREENLAND */
    {wifi_countrycode_GM,"GM"}, /**< GAMBIA */
    {wifi_countrycode_GN,"GN"}, /**< GUINEA */
    {wifi_countrycode_GP,"GP"}, /**< GUADELOUPE */
    {wifi_countrycode_GQ,"GQ"}, /**< EQUATORIAL GUINEA */
    {wifi_countrycode_GR,"GR"}, /**< GREECE */
    {wifi_countrycode_GS,"GS"}, /**< SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS */
    {wifi_countrycode_GT,"GT"}, /**< GUATEMALA */
    {wifi_countrycode_GU,"GU"}, /**< GUAM */
    {wifi_countrycode_GW,"GW"}, /**< GUINEA-BISSAU */
    {wifi_countrycode_GY,"GY"}, /**< GUYANA */
    {wifi_countrycode_HR,"HR"}, /**< CROATIA */
    {wifi_countrycode_HT,"HT"}, /**< HAITI */
    {wifi_countrycode_HM,"HM"}, /**< HEARD ISLAND AND MCDONALD ISLANDS */
    {wifi_countrycode_HN,"HN"}, /**< HONDURAS */
    {wifi_countrycode_HK,"HK"}, /**< HONG KONG */
    {wifi_countrycode_HU,"HU"}, /**< HUNGARY */
    {wifi_countrycode_IS,"IS"}, /**< ICELAND */
    {wifi_countrycode_IN,"IN"}, /**< INDIA */
    {wifi_countrycode_ID,"ID"}, /**< INDONESIA */
    {wifi_countrycode_IR,"IR"}, /**< IRAN, ISLAMIC REPUBLIC OF */
    {wifi_countrycode_IQ,"IQ"}, /**< IRAQ */
    {wifi_countrycode_IE,"IE"}, /**< IRELAND */
    {wifi_countrycode_IL,"IL"}, /**< ISRAEL */
    {wifi_countrycode_IM,"IM"}, /**< MAN, ISLE OF */
    {wifi_countrycode_IT,"IT"}, /**< ITALY */
    {wifi_countrycode_IO,"IO"}, /**< BRITISH INDIAN OCEAN TERRITORY */
    {wifi_countrycode_JM,"JM"}, /**< JAMAICA */
    {wifi_countrycode_JP,"JP"}, /**< JAPAN */
    {wifi_countrycode_JE,"JE"}, /**< JERSEY */
    {wifi_countrycode_JO,"jo"}, /**< JORDAN */
    {wifi_countrycode_KE,"KE"}, /**< KENYA */
    {wifi_countrycode_KG,"KG"}, /**< KYRGYZSTAN */
    {wifi_countrycode_KH,"KH"}, /**< CAMBODIA */
    {wifi_countrycode_KI,"KI"}, /**< KIRIBATI */
    {wifi_countrycode_KM,"KM"}, /**< COMOROS */
    {wifi_countrycode_KN,"KN"}, /**< SAINT KITTS AND NEVIS */
    {wifi_countrycode_KP,"KP"}, /**< KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF */
    {wifi_countrycode_KR,"KR"}, /**< KOREA, REPUBLIC OF */
    {wifi_countrycode_KW,"KW"}, /**< KUWAIT */
    {wifi_countrycode_KY,"KY"}, /**< CAYMAN ISLANDS */
    {wifi_countrycode_KZ,"KZ"}, /**< KAZAKHSTAN */
    {wifi_countrycode_LA,"LA"}, /**< LAO PEOPLE'S DEMOCRATIC REPUBLIC */
    {wifi_countrycode_LB,"LB"}, /**< LEBANON */
    {wifi_countrycode_LC,"LC"}, /**< SAINT LUCIA */
    {wifi_countrycode_LI,"LI"}, /**< LIECHTENSTEIN */
    {wifi_countrycode_LK,"LK"}, /**< SRI LANKA */
    {wifi_countrycode_LR,"LR"}, /**< LIBERIA */
    {wifi_countrycode_LS,"LS"}, /**< LESOTHO */
    {wifi_countrycode_LT,"LT"}, /**< LITHUANIA */
    {wifi_countrycode_LU,"LU"}, /**< LUXEMBOURG */
    {wifi_countrycode_LV,"LV"}, /**< LATVIA */
    {wifi_countrycode_LY,"LY"}, /**< LIBYAN ARAB JAMAHIRIYA */
    {wifi_countrycode_MA,"MA"}, /**< MOROCCO */
    {wifi_countrycode_MC,"MC"}, /**< MONACO */
    {wifi_countrycode_MD,"MD"}, /**< MOLDOVA, REPUBLIC OF */
    {wifi_countrycode_ME,"ME"}, /**< MONTENEGRO */
    {wifi_countrycode_MG,"MG"}, /**< MADAGASCAR */
    {wifi_countrycode_MH,"MH"}, /**< MARSHALL ISLANDS */
    {wifi_countrycode_MK,"MK"}, /**< MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF */
    {wifi_countrycode_ML,"ML"}, /**< MALI */
    {wifi_countrycode_MM,"MM"}, /**< MYANMAR */
    {wifi_countrycode_MN,"MN"}, /**< MONGOLIA */
    {wifi_countrycode_MO,"MO"}, /**< MACAO */
    {wifi_countrycode_MQ,"MQ"}, /**< MARTINIQUE */
    {wifi_countrycode_MR,"MR"}, /**< MAURITANIA */
    {wifi_countrycode_MS,"MS"}, /**< MONTSERRAT */
    {wifi_countrycode_MT,"MT"}, /**< MALTA */
    {wifi_countrycode_MU,"MU"}, /**< MAURITIUS */
    {wifi_countrycode_MV,"MV"}, /**< MALDIVES */
    {wifi_countrycode_MW,"MW"}, /**< MALAWI */
    {wifi_countrycode_MX,"MX"}, /**< MEXICO */
    {wifi_countrycode_MY,"MY"}, /**< MALAYSIA */
    {wifi_countrycode_MZ,"MZ"}, /**< MOZAMBIQUE */
    {wifi_countrycode_NA,"NA"}, /**< NAMIBIA */
    {wifi_countrycode_NC,"NC"}, /**< NEW CALEDONIA */
    {wifi_countrycode_NE,"NE"}, /**< NIGER */
    {wifi_countrycode_NF,"NF"}, /**< NORFOLK ISLAND */
    {wifi_countrycode_NG,"NG"}, /**< NIGERIA */
    {wifi_countrycode_NI,"NI"}, /**< NICARAGUA */
    {wifi_countrycode_NL,"NL"}, /**< NETHERLANDS */
    {wifi_countrycode_NO,"NO"}, /**< NORWAY */
    {wifi_countrycode_NP,"NP"}, /**< NEPAL */
    {wifi_countrycode_NR,"NR"}, /**< NAURU */
    {wifi_countrycode_NU,"NU"}, /**< NIUE */
    {wifi_countrycode_NZ,"NZ"}, /**< NEW ZEALAND */
    {wifi_countrycode_MP,"MP"}, /**< NORTHERN MARIANA ISLANDS */
    {wifi_countrycode_OM,"OM"}, /**< OMAN */
    {wifi_countrycode_PA,"PA"}, /**< PANAMA */
    {wifi_countrycode_PE,"PE"}, /**< PERU */
    {wifi_countrycode_PF,"PF"}, /**< FRENCH POLYNESIA */
    {wifi_countrycode_PG,"PG"}, /**< PAPUA NEW GUINEA */
    {wifi_countrycode_PH,"PH"}, /**< PHILIPPINES */
    {wifi_countrycode_PK,"PK"}, /**< PAKISTAN */
    {wifi_countrycode_PL,"PL"}, /**< POLAND */
    {wifi_countrycode_PM,"PM"}, /**< SAINT PIERRE AND MIQUELON */
    {wifi_countrycode_PN,"PN"}, /**< PITCAIRN */
    {wifi_countrycode_PR,"PR"}, /**< PUERTO RICO */
    {wifi_countrycode_PS,"PS"}, /**< PALESTINIAN TERRITORY,OCCUPIED */
    {wifi_countrycode_PT,"PT"}, /**< PORTUGAL */
    {wifi_countrycode_PW,"PW"}, /**< PALAU */
    {wifi_countrycode_PY,"PY"}, /**< PARAGUAY */
    {wifi_countrycode_QA,"QA"}, /**< QATAR */
    {wifi_countrycode_RE,"RE"}, /**< REUNION */
    {wifi_countrycode_RO,"RO"}, /**< ROMANIA */
    {wifi_countrycode_RS,"RS"}, /**< SERBIA */
    {wifi_countrycode_RU,"RU"}, /**< RUSSIAN FEDERATION */
    {wifi_countrycode_RW,"RW"}, /**< RWANDA */
    {wifi_countrycode_SA,"SA"}, /**< SAUDI ARABIA */
    {wifi_countrycode_SB,"SB"}, /**< SOLOMON ISLANDS */
    {wifi_countrycode_SD,"SD"}, /**< SUDAN */
    {wifi_countrycode_SE,"SE"}, /**< SWEDEN */
    {wifi_countrycode_SC,"SC"}, /**< SEYCHELLES */
    {wifi_countrycode_SG,"SG"}, /**< SINGAPORE */
    {wifi_countrycode_SH,"SH"}, /**< SAINT HELENA */
    {wifi_countrycode_SI,"SI"}, /**< SLOVENIA */
    {wifi_countrycode_SJ,"SJ"}, /**< SVALBARD AND JAN MAYEN */
    {wifi_countrycode_SK,"SK"}, /**< SLOVAKIA */
    {wifi_countrycode_SL,"SL"}, /**< SIERRA LEONE */
    {wifi_countrycode_SM,"SM"}, /**< SAN MARINO */
    {wifi_countrycode_SN,"SN"}, /**< SENEGAL */
    {wifi_countrycode_SO,"SO"}, /**< SOMALIA */
    {wifi_countrycode_SR,"SR"}, /**< SURINAME */
    {wifi_countrycode_ST,"ST"}, /**< SAO TOME AND PRINCIPE */
    {wifi_countrycode_SV,"SV"}, /**< EL SALVADOR */
    {wifi_countrycode_SY,"SY"}, /**< SYRIAN ARAB REPUBLIC */
    {wifi_countrycode_SZ,"SZ"}, /**< SWAZILAND */
    {wifi_countrycode_TA,"TA"}, /**< TRISTAN DA CUNHA */
    {wifi_countrycode_TC,"TC"}, /**< TURKS AND CAICOS ISLANDS */
    {wifi_countrycode_TD,"TD"}, /**< CHAD */
    {wifi_countrycode_TF,"TF"}, /**< FRENCH SOUTHERN TERRITORIES */
    {wifi_countrycode_TG,"TG"}, /**< TOGO */
    {wifi_countrycode_TH,"TH"}, /**< THAILAND */
    {wifi_countrycode_TJ,"TJ"}, /**< TAJIKISTAN */
    {wifi_countrycode_TK,"TK"}, /**< TOKELAU */
    {wifi_countrycode_TL,"TL"}, /**< TIMOR-LESTE (EAST TIMOR) */
    {wifi_countrycode_TM,"TM"}, /**< TURKMENISTAN */
    {wifi_countrycode_TN,"TN"}, /**< TUNISIA */
    {wifi_countrycode_TO,"TO"}, /**< TONGA */
    {wifi_countrycode_TR,"TR"}, /**< TURKEY */
    {wifi_countrycode_TT,"TT"}, /**< TRINIDAD AND TOBAGO */
    {wifi_countrycode_TV,"TV"}, /**< TUVALU */
    {wifi_countrycode_TW,"TW"}, /**< TAIWAN, PROVINCE OF CHINA */
    {wifi_countrycode_TZ,"TZ"}, /**< TANZANIA, UNITED REPUBLIC OF */
    {wifi_countrycode_UA,"UA"}, /**< UKRAINE */
    {wifi_countrycode_UG,"UG"}, /**< UGANDA */
    {wifi_countrycode_UM,"UM"}, /**< UNITED STATES MINOR OUTLYING ISLANDS */
    {wifi_countrycode_US,"US"}, /**< UNITED STATES */
    {wifi_countrycode_UY,"UY"}, /**< URUGUAY */
    {wifi_countrycode_UZ,"UZ"}, /**< UZBEKISTAN */
    {wifi_countrycode_VA,"VA"}, /**< HOLY SEE (VATICAN CITY STATE) */
    {wifi_countrycode_VC,"VC"}, /**< SAINT VINCENT AND THE GRENADINES */
    {wifi_countrycode_VE,"VE"}, /**< VENEZUELA */
    {wifi_countrycode_VG,"VG"}, /**< VIRGIN ISLANDS, BRITISH */
    {wifi_countrycode_VI,"VI"}, /**< VIRGIN ISLANDS, U.S. */
    {wifi_countrycode_VN,"VN"}, /**< VIET NAM */
    {wifi_countrycode_VU,"VU"}, /**< VANUATU */
    {wifi_countrycode_WF,"WF"}, /**< WALLIS AND FUTUNA */
    {wifi_countrycode_WS,"WS"}, /**< SAMOA */
    {wifi_countrycode_YE,"YE"}, /**< YEMEN */
    {wifi_countrycode_YT,"YT"}, /**< MAYOTTE */
    {wifi_countrycode_YU,"YU"}, /**< YUGOSLAVIA */
    {wifi_countrycode_ZA,"ZA"}, /**< SOUTH AFRICA */
    {wifi_countrycode_ZM,"ZM"}, /**< ZAMBIA */
    {wifi_countrycode_ZW,"ZW"} /**< ZIMBABWE */
};

struct wifiEnvironmentEnumStrMap wifi_environment_map[] =
{
    {wifi_operating_env_all, " "},
    {wifi_operating_env_indoor, "I"},
    {wifi_operating_env_outdoor, "O"},
    {wifi_operating_env_non_country, "X"}
};

static const char *const us_op_class_cc[] = {
        "US", "CA", NULL
};

static const char *const eu_op_class_cc[] = {
        "AL", "AM", "AT", "AZ", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE",
        "DK", "EE", "EL", "ES", "FI", "FR", "GE", "HR", "HU", "IE", "IS", "IT",
        "LI", "LT", "LU", "LV", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT",
        "RO", "RS", "RU", "SE", "SI", "SK", "TR", "UA", "GB", NULL
};

static const char *const jp_op_class_cc[] = {
        "JP", NULL
};

static const char *const cn_op_class_cc[] = {
        "CN", NULL
};

wifi_country_radio_op_class_t us_op_class = {
    wifi_countrycode_US,
    {
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 3, 124, 4, {149, 153, 157, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 4, 121, 12, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 0, 0, 0, 0} },
        { 5, 125, 5, {149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 12, 81, 11, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0} }
    }
};

wifi_country_radio_op_class_t eu_op_class = {
    wifi_countrycode_AT,
    {
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 3, 121, 11, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 0, 0, 0, 0, 0} },
        { 4, 81, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} },
        { 5, 116, 2, {36, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 6, 119, 2, {52, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
    }
};

wifi_country_radio_op_class_t jp_op_class = {
    wifi_countrycode_JP,
    {
        { 30, 81, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} },
        { 31, 82, 1, {14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 32, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 34, 121, 11, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 0, 0, 0, 0, 0} },
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 58, 121, 11, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 0, 0, 0, 0, 0} }
    }
};

wifi_country_radio_op_class_t cn_op_class = {
    wifi_countrycode_CN,
    {
        { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 3, 125, 5, {149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 4, 116, 2, {36, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 5, 119, 2, {52, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 7, 81, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} }
    }
};

/* We need to update correct country global oprating class information */
wifi_country_radio_op_class_t other_op_class = {
    wifi_countrycode_IN,
    {
        { 81, 0, 13, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0} },
        { 82, 0, 1, {14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 115, 0, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 121, 0, 12, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 0, 0, 0, 0} },
        { 124, 0, 4, {149, 153, 157, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
        { 125, 0, 6, {149, 153, 157, 161, 165, 169, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
    }
};

BOOL is_wifi_hal_vap_private(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "private_ssid", strlen("private_ssid")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_xhs(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "iot_ssid", strlen("iot_ssid")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot", strlen("hotspot")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot_from_interfacename(char *interface_name)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((strcmp(interface_index_map[index].interface_name, interface_name) == 0) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot", strlen("hotspot")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot_open(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot_open", strlen("hotspot_open")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_lnf(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "lnf", strlen("lnf")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_lnf_psk(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "lnf_psk", strlen("lnf_psk")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_mesh(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "mesh", strlen("mesh")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_mesh_backhaul(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "mesh_backhaul", strlen("mesh_backhaul")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_hotspot_secure(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "hotspot_secure", strlen("hotspot_secure")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_lnf_radius(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "lnf_radius", strlen("lnf_radius")) == 0)) {
            return true;
        }
    }
    return false;
}

BOOL is_wifi_hal_vap_mesh_sta(UINT ap_index)
{
    unsigned char index = 0;
    for (index = 0; index < ARRAY_SZ(interface_index_map); index++) {
        if ((interface_index_map[index].index == ap_index) &&
                (strncmp(interface_index_map[index].vap_name, "mesh_sta", strlen("mesh_sta")) == 0)) {
            return true;
        }
    }
    return false;
}

wifi_enum_to_str_map_t wifi_variant_Map[] =
{
    {WIFI_80211_VARIANT_A,  "a"},
    {WIFI_80211_VARIANT_B,  "b"},
    {WIFI_80211_VARIANT_G,  "g"},
    {WIFI_80211_VARIANT_N,  "n"},
    {WIFI_80211_VARIANT_AC, "ac"},
    {WIFI_80211_VARIANT_AD, "ad"},
    {WIFI_80211_VARIANT_AX, "ax"}
};

int get_rdk_radio_index(unsigned int phy_index)
{
    wifi_interface_name_idex_map_t *map;
    unsigned int i;
    for (i = 0; i < sizeof(interface_index_map)/sizeof(wifi_interface_name_idex_map_t); i++) {
        map = &interface_index_map[i];
        if ( phy_index == map->phy_index ) {
            return map->rdk_radio_index;
        }
    }
    return -1;
}

int is_backhaul_interface(wifi_interface_info_t *interface)
{
    wifi_vap_info_t *vap;

    vap = &interface->vap_info;
    return (strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) == 0) ? true : false;
}

void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map)
{
    memcpy(interface_map, interface_index_map, sizeof(interface_index_map));
}

int get_ap_vlan_id(char *interface_name)
{
    int i = 0;
    wifi_interface_name_idex_map_t *map = NULL;
    for (i = 0; i < sizeof(interface_index_map)/sizeof(wifi_interface_name_idex_map_t); i++) {
        map = &interface_index_map[i];
        if ((strcmp(interface_name, map->interface_name) == 0))  {
            wifi_hal_dbg_print("get_ap_vlan_id %d and returned val is %d\n",map->vlan_id,&interface_index_map[i].vlan_id);
            return map->vlan_id;
        }
   }
   return -1;
}

wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        if (interface->primary == true) {
            return interface;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    return NULL;
}

wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        vap = &interface->vap_info;
        if (!strncmp(vap->vap_name, "private_ssid_", strlen("private_ssid_"))) {
            return interface;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }
    return NULL;
}
int getIpStringFromAdrress (char * ipString, ip_addr_t * ip)
{
    if (ip->family == wifi_ip_family_ipv4) {
        inet_ntop(AF_INET, &ip->u.IPv4addr, ipString, INET_ADDRSTRLEN);
    }
    else if (ip->family == wifi_ip_family_ipv6) {
        inet_ntop(AF_INET6, &ip->u.IPv6addr, ipString, INET_ADDRSTRLEN);
    }
    else {
        strcpy(ipString,"0.0.0.0");
        wifi_hal_error_print("%s IP not recognised\n", __func__);
        return 0;
    }

    return 1;
}


int set_interface_properties(unsigned int phy_index, wifi_interface_info_t *interface)
{
    wifi_interface_name_idex_map_t *map;
    wifi_vap_info_t *vap;
    unsigned int i;
    bool found = false;

    vap = &interface->vap_info;

    vap->vap_index = 0;

    for (i = 0; i < sizeof(interface_index_map)/sizeof(wifi_interface_name_idex_map_t); i++) {
        map = &interface_index_map[i];

        if ((strcmp(interface->name, map->interface_name) == 0) &&
            (phy_index == map->phy_index)) {
            vap->radio_index = map->rdk_radio_index;
            vap->vap_index = map->index;
            strcpy(vap->vap_name, map->vap_name);
            interface->primary = map->primary;
            found = true;
            break;
        }
    }

    if (!found) {
        wifi_hal_error_print("%s:%d phy_index %d interface%s not found\n", __func__, __LINE__,  phy_index, interface->name);
    }

    return (found == true) ? 0 : -1;
}

int get_interface_name_from_vap_index(unsigned int vap_index, char *interface_name)
{
    // OneWifi interafce mapping with vap_index
    unsigned char l_index = 0;
    unsigned char total_num_of_vaps = 0;
    char *l_interface_name = NULL;
    wifi_radio_info_t *radio;

    for (l_index = 0; l_index < g_wifi_hal.num_radios; l_index++) {
        radio = get_radio_by_rdk_index(l_index);
        total_num_of_vaps += radio->capab.maxNumberVAPs;
    }

    if ((vap_index >= total_num_of_vaps) || (interface_name == NULL)) {
        wifi_hal_error_print("%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    l_interface_name = bss_nvifname[vap_index];
    if(l_interface_name != NULL) {
        strncpy(interface_name, l_interface_name, (strlen(l_interface_name) + 1));
        wifi_hal_dbg_print("%s:%d: VAP index %d: interface name %s\n", __func__, __LINE__, vap_index, interface_name);
    } else {
        wifi_hal_error_print("%s:%d: Interface name not found:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}


wifi_radio_info_t *get_radio_by_phy_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->index == index) {
            return radio;
        }
    }

    return NULL;
}

wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    wifi_hal_dbg_print("%s:%d:{ vap_index:[%d] } g_wifi_hal.num_radios:[%d]\r\n",__func__, __LINE__, vap_index, g_wifi_hal.num_radios);
    for (i = 0; i < g_wifi_hal.num_radios; i++) {

        radio = &g_wifi_hal.radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            wifi_hal_dbg_print("%s:%d:interface vap_index:[%d] vap_index:[%d]\r\n",__func__, __LINE__, interface->vap_info.vap_index, vap_index);
            if (interface->vap_info.vap_index == vap_index) {
                return interface;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    return NULL;
}

BOOL get_ie_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, unsigned short *ie_out_len)
{
    ieee80211_tlv_t *ie = NULL;
    signed int len;

    ie = (ieee80211_tlv_t *)buff;
    len = buff_len;

    while ((ie != NULL) && (len > 0)) {
        if ((ie->type == eid) && (ie->length != 0)) {
            //wifi_hal_dbg_print("%s:%d: Found ssid ie, ie length:%d\n", __func__, __LINE__,
            //    ie->length);
            *ie_out = (unsigned char *)ie;
            *ie_out_len = ie->length + sizeof(ieee80211_tlv_t);
            return true;
        }

        len = len - (ie->length + sizeof(ieee80211_tlv_t));
        ie = (ieee80211_tlv_t *)((unsigned char *)ie + (ie->length + sizeof(ieee80211_tlv_t)));
    }

    return false;
}

int get_radio_variant_str_from_int(unsigned char variant, char *variant_str)
{
    unsigned char index = 0;
    char temp_variant_str[24];
    memset(temp_variant_str, 0, sizeof(temp_variant_str));

    if ((variant == 0) || (variant_str == NULL)) {
        wifi_hal_error_print("%s:%d: variant value zero:%d\n", __func__, __LINE__, variant);
        return RETURN_ERR;
    }

    for (index = 0; index < ARRAY_SIZE(wifi_variant_Map); index++) {
        if ((variant & wifi_variant_Map[index].enum_val) && (strlen(temp_variant_str) == 0)) {
            strcpy(temp_variant_str, wifi_variant_Map[index].str_val);
        } else if (variant & wifi_variant_Map[index].enum_val) {
            strcat(temp_variant_str, ",");
            strcat(temp_variant_str, wifi_variant_Map[index].str_val);
        }
    }

    strncpy(variant_str, temp_variant_str, strlen(temp_variant_str));

    return RETURN_OK;
}

int get_vap_mode_str_from_int_mode(unsigned char vap_mode, char *vap_mode_str)
{
    switch (vap_mode) {
    case wifi_vap_mode_ap:
        strcpy(vap_mode_str, "ap");
        break;

    case wifi_vap_mode_sta:
        strcpy(vap_mode_str, "sta");
        break;

    case wifi_vap_mode_monitor:
        strcpy(vap_mode_str, "monitor");
        break;

    default:
        strcpy(vap_mode_str, "none");
        break;
    }

    return RETURN_OK;
}

int get_security_mode_support_radius(int mode)
{
    int sec_mode = 0;
    if ((mode == wifi_security_mode_wpa_enterprise) || (mode == wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)){
        sec_mode = 1;
    } else {
        sec_mode = 0;
    }

    return sec_mode;
}

int get_security_mode_str_from_int(wifi_security_modes_t security_mode, char *security_mode_str)
{
    switch (security_mode) {
    case wifi_security_mode_none:
        strcpy(security_mode_str, "None");
        break;

    case wifi_security_mode_wpa_personal:
        strcpy(security_mode_str, "psk");
        break;

    case wifi_security_mode_wpa2_personal:
        strcpy(security_mode_str, "psk2");
        break;

    case wifi_security_mode_wpa_wpa2_personal:
        strcpy(security_mode_str, "psk psk2");
        break;

    case wifi_security_mode_wpa3_personal:
        strcpy(security_mode_str, "sae");
        break;

    case wifi_security_mode_wpa3_transition:
        strcpy(security_mode_str, "psk2 sae");
        break;

    case wifi_security_mode_wpa_enterprise:
        strcpy(security_mode_str, "wpa");
        break;

    case wifi_security_mode_wpa2_enterprise:
        strcpy(security_mode_str, "wpa2");
        break;

    case wifi_security_mode_wpa3_enterprise:
        strcpy(security_mode_str, "wpa2");
        break;

    case wifi_security_mode_wpa_wpa2_enterprise:
        strcpy(security_mode_str, "wpa wpa2");
        break;

    default:
        wifi_hal_error_print("%s:%d: wifi security mode not found:[%d]\r\n",__func__, __LINE__, security_mode);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_security_encryption_mode_str_from_int(wifi_encryption_method_t encryption_mode, char *encryption_mode_str)
{
    switch (encryption_mode) {
    case wifi_encryption_none:
        strcpy(encryption_mode_str, "none");
        break;

    case wifi_encryption_tkip:
        strcpy(encryption_mode_str, "tkip");
        break;

    case wifi_encryption_aes:
        strcpy(encryption_mode_str, "aes");
        break;

    case wifi_encryption_aes_tkip:
        strcpy(encryption_mode_str, "tkip+aes");
        break;

    default:
        wifi_hal_error_print("%s:%d: wifi encryption method not found:[%d]\r\n",__func__, __LINE__, encryption_mode);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT get_coutry_str_from_oper_params(wifi_radio_operationParam_t *operParams, char *country)
{
    unsigned int index = 0;
    char tmp_countrycode_str[4];
    char tmp_environment_str[4];

    memset(tmp_countrycode_str, 0, sizeof(tmp_countrycode_str));
    memset(tmp_environment_str, 0, sizeof(tmp_environment_str));
    
    // Default country as "USI"
    strcpy(tmp_countrycode_str, "US");
    strcpy(tmp_environment_str, "I");

    for (index = 0; index < ARRAY_SZ(wifi_country_map); index++) {
        if (wifi_country_map[index].countryCode == operParams->countryCode) {
            strncpy(tmp_countrycode_str, wifi_country_map[index].countryStr, sizeof(wifi_country_map[index].countryStr)-1);
            break;
        }
    }

    for (index = 0; index < ARRAY_SZ(wifi_environment_map); index++) {
        if (wifi_environment_map[index].operatingEnvironment == operParams->operatingEnvironment) {
            strncpy(tmp_environment_str, wifi_environment_map[index].environment, sizeof(wifi_environment_map[index].environment)-1);
            break;
        }
    }

    snprintf(country, 4, "%s%s", tmp_countrycode_str, tmp_environment_str);

    return RETURN_OK;
}

INT get_coutry_str_from_code(wifi_countrycode_type_t code, char *country)
{
    unsigned int index = 0;
    bool value_updated = false;

    for (index = 0; index < ARRAY_SZ(wifi_country_map); index++) {
        if (wifi_country_map[index].countryCode == code) {
            strcpy(country, wifi_country_map[index].countryStr);
            value_updated = true;
            break;
        }
    }

    if (value_updated == false) {
        //Copy default value
        strcpy(country, "US");
    }

    return RETURN_OK;
}

static int find_country_code_match(const char *const cc[], const char *const country)
{
    int i;

    if (country == NULL) {
        return RETURN_ERR;
    }

    for (i = 0; cc[i]; i++) {
        if (cc[i][0] == country[0] && cc[i][1] == country[1]) {
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}

int get_wifi_op_class_info(wifi_countrycode_type_t country_code, wifi_country_radio_op_class_t *op_classes)
{
    if (country_code > wifi_countrycode_ZW) {
        wifi_hal_dbg_print("%s:%d: Wrong country code:%d\n", __func__, __LINE__, country_code);
        return RETURN_ERR;
    }

    char str_country[4];
    int ret;

    memset(str_country, 0, sizeof(str_country));
    get_coutry_str_from_code(country_code, str_country);

    ret = find_country_code_match(us_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &us_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }
    ret = find_country_code_match(eu_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &eu_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }
    ret = find_country_code_match(jp_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &jp_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }
    ret = find_country_code_match(cn_op_class_cc, str_country);
    if (ret == RETURN_OK) {
        memcpy(op_classes, &cn_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    } else {
        memcpy(op_classes, &other_op_class, sizeof(wifi_country_radio_op_class_t));
        op_classes->cc = country_code;
        return RETURN_OK;
    }

    return RETURN_OK;
}

int get_op_class_from_radio_params(wifi_radio_operationParam_t *param)
{
    unsigned int i, j;
    wifi_country_radio_op_class_t cc_op_class;
    wifi_radio_op_class_t   *op_class;

#if HOSTAPD_VERSION >= 210 //2.10
    if (param->band == WIFI_FREQUENCY_6_BAND) {
        int freq, global_op_class = -1;

        freq = (param->channel == 2) ? 5935 : (5950 + (param->channel * 5));
        if (is_6ghz_freq(freq)) {
            global_op_class = 131 + center_idx_to_bw_6ghz(param->channel);
        }
        return global_op_class;
    }
#endif

    memset(&cc_op_class, 0, sizeof(cc_op_class));

    get_wifi_op_class_info(param->countryCode, &cc_op_class);

    // country code match
    if (cc_op_class.cc != param->countryCode) {
        wifi_hal_error_print("%s:%d:Could not find country code : %d\n", __func__, __LINE__, param->countryCode);
        return RETURN_ERR;
    }

    // channel match
    for (i = 0; i < ARRAY_SZ(cc_op_class.op_class); i++) {
        op_class = &cc_op_class.op_class[i];
        for (j = 0; j < op_class->num; j++) {
            if (op_class->ch_list[j] == param->channel) {
                return op_class->op_class;
            }
        }
    }

    wifi_hal_error_print("%s:%d:Could not find channel is list for country : %d\n", __func__, __LINE__, param->countryCode);
    return RETURN_ERR;
}



void wifi_hal_print(wifi_hal_log_level_t level, char *format, ...)
{
    char buff[256] = {0};
    va_list list;
    FILE *fpg = NULL;

    get_formatted_time(buff);

#ifdef LINUX_VM_PORT
    printf("%s ", buff);
    va_start(list, format);
    vprintf (format, list);
    va_end(list);
#else
    if ((access("/nvram/wifiHalDbg", R_OK)) == 0) {

        fpg = fopen("/tmp/wifiHal", "a+");
        if (fpg == NULL) {
            return;
        }
    } else {
        switch (level) {
            case WIFI_HAL_LOG_LVL_INFO:
            case WIFI_HAL_LOG_LVL_ERROR:
                fpg = fopen("/rdklogs/logs/wifiHal.txt", "a+");
                if (fpg == NULL) {
                    return;
                }
            break;
            case WIFI_HAL_LOG_LVL_DEBUG:
            default:
                return;
        }
    }

    fprintf(fpg, "%s ", buff);
    va_start(list, format);
    vfprintf(fpg, format, list);
    va_end(list);
    fflush(fpg);
    fclose(fpg);
#endif
    return;
}

const char *wpa_alg_to_string(enum wpa_alg alg)
{
#define ALG2S(x) case x: return #x;
    switch (alg) {
    ALG2S(WPA_ALG_NONE)
    ALG2S(WPA_ALG_WEP)
    ALG2S(WPA_ALG_TKIP)
    ALG2S(WPA_ALG_CCMP)
#if HOSTAPD_VERSION >= 210 //2.10
    ALG2S(WPA_ALG_BIP_CMAC_128)
#else
    ALG2S(WPA_ALG_IGTK)
    ALG2S(WPA_ALG_PMK)
#endif
    ALG2S(WPA_ALG_GCMP)
    ALG2S(WPA_ALG_SMS4)
    ALG2S(WPA_ALG_KRK)
    ALG2S(WPA_ALG_GCMP_256)
    ALG2S(WPA_ALG_CCMP_256)
    ALG2S(WPA_ALG_BIP_GMAC_128)
    ALG2S(WPA_ALG_BIP_GMAC_256)
    ALG2S(WPA_ALG_BIP_CMAC_256)
    }

    return "WPA_ALG_UNKNOWN";
}

const char *nl80211_attribute_to_string(enum nl80211_attrs attrib)
{
#define A2S(x) case x: return #x;
    switch (attrib) {
    A2S(NL80211_ATTR_UNSPEC)

    A2S(NL80211_ATTR_WIPHY)
    A2S(NL80211_ATTR_WIPHY_NAME)

    A2S(NL80211_ATTR_IFINDEX)
    A2S(NL80211_ATTR_IFNAME)
    A2S(NL80211_ATTR_IFTYPE)

    A2S(NL80211_ATTR_MAC)

    A2S(NL80211_ATTR_KEY_DATA)
    A2S(NL80211_ATTR_KEY_IDX)
    A2S(NL80211_ATTR_KEY_CIPHER)
    A2S(NL80211_ATTR_KEY_SEQ)
    A2S(NL80211_ATTR_KEY_DEFAULT)

    A2S(NL80211_ATTR_BEACON_INTERVAL)
    A2S(NL80211_ATTR_DTIM_PERIOD)
    A2S(NL80211_ATTR_BEACON_HEAD)
    A2S(NL80211_ATTR_BEACON_TAIL)

    A2S(NL80211_ATTR_STA_AID)
    A2S(NL80211_ATTR_STA_FLAGS)
    A2S(NL80211_ATTR_STA_LISTEN_INTERVAL)
    A2S(NL80211_ATTR_STA_SUPPORTED_RATES)
    A2S(NL80211_ATTR_STA_VLAN)
    A2S(NL80211_ATTR_STA_INFO)

    A2S(NL80211_ATTR_WIPHY_BANDS)

    A2S(NL80211_ATTR_MNTR_FLAGS)

    A2S(NL80211_ATTR_MESH_ID)
    A2S(NL80211_ATTR_STA_PLINK_ACTION)
    A2S(NL80211_ATTR_MPATH_NEXT_HOP)
    A2S(NL80211_ATTR_MPATH_INFO)

    A2S(NL80211_ATTR_BSS_CTS_PROT)
    A2S(NL80211_ATTR_BSS_SHORT_PREAMBLE)
    A2S(NL80211_ATTR_BSS_SHORT_SLOT_TIME)

    A2S(NL80211_ATTR_HT_CAPABILITY)

    A2S(NL80211_ATTR_SUPPORTED_IFTYPES)

    A2S(NL80211_ATTR_REG_ALPHA2)
    A2S(NL80211_ATTR_REG_RULES)

    A2S(NL80211_ATTR_MESH_CONFIG)

    A2S(NL80211_ATTR_BSS_BASIC_RATES)

    A2S(NL80211_ATTR_WIPHY_TXQ_PARAMS)
    A2S(NL80211_ATTR_WIPHY_FREQ)
    A2S(NL80211_ATTR_WIPHY_CHANNEL_TYPE)

    A2S(NL80211_ATTR_KEY_DEFAULT_MGMT)

    A2S(NL80211_ATTR_MGMT_SUBTYPE)
    A2S(NL80211_ATTR_IE)

    A2S(NL80211_ATTR_MAX_NUM_SCAN_SSIDS)

    A2S(NL80211_ATTR_SCAN_FREQUENCIES)
    A2S(NL80211_ATTR_SCAN_SSIDS)
    A2S(NL80211_ATTR_GENERATION) /* replaces old SCAN_GENERATION */
    A2S(NL80211_ATTR_BSS)

    A2S(NL80211_ATTR_REG_INITIATOR)
    A2S(NL80211_ATTR_REG_TYPE)

    A2S(NL80211_ATTR_SUPPORTED_COMMANDS)

    A2S(NL80211_ATTR_FRAME)
    A2S(NL80211_ATTR_SSID)
    A2S(NL80211_ATTR_AUTH_TYPE)
    A2S(NL80211_ATTR_REASON_CODE)

    A2S(NL80211_ATTR_KEY_TYPE)
    A2S(NL80211_ATTR_MAX_SCAN_IE_LEN)
    A2S(NL80211_ATTR_CIPHER_SUITES)

    A2S(NL80211_ATTR_FREQ_BEFORE)
    A2S(NL80211_ATTR_FREQ_AFTER)

    A2S(NL80211_ATTR_FREQ_FIXED)


    A2S(NL80211_ATTR_WIPHY_RETRY_SHORT)
    A2S(NL80211_ATTR_WIPHY_RETRY_LONG)
    A2S(NL80211_ATTR_WIPHY_FRAG_THRESHOLD)
    A2S(NL80211_ATTR_WIPHY_RTS_THRESHOLD)

    A2S(NL80211_ATTR_TIMED_OUT)

    A2S(NL80211_ATTR_USE_MFP)

    A2S(NL80211_ATTR_STA_FLAGS2)

    A2S(NL80211_ATTR_CONTROL_PORT)

    A2S(NL80211_ATTR_TESTDATA)

    A2S(NL80211_ATTR_PRIVACY)

    A2S(NL80211_ATTR_DISCONNECTED_BY_AP)
    A2S(NL80211_ATTR_STATUS_CODE)

    A2S(NL80211_ATTR_CIPHER_SUITES_PAIRWISE)
    A2S(NL80211_ATTR_CIPHER_SUITE_GROUP)
    A2S(NL80211_ATTR_WPA_VERSIONS)
    A2S(NL80211_ATTR_AKM_SUITES)

    A2S(NL80211_ATTR_REQ_IE)
    A2S(NL80211_ATTR_RESP_IE)

    A2S(NL80211_ATTR_PREV_BSSID)
    A2S(NL80211_ATTR_KEY)
    A2S(NL80211_ATTR_KEYS)

    A2S(NL80211_ATTR_PID)

    A2S(NL80211_ATTR_4ADDR)

    A2S(NL80211_ATTR_SURVEY_INFO)

    A2S(NL80211_ATTR_PMKID)
    A2S(NL80211_ATTR_MAX_NUM_PMKIDS)

    A2S(NL80211_ATTR_DURATION)

    A2S(NL80211_ATTR_COOKIE)

    A2S(NL80211_ATTR_WIPHY_COVERAGE_CLASS)

    A2S(NL80211_ATTR_TX_RATES)

    A2S(NL80211_ATTR_FRAME_MATCH)

    A2S(NL80211_ATTR_ACK)

    A2S(NL80211_ATTR_PS_STATE)

    A2S(NL80211_ATTR_CQM)

    A2S(NL80211_ATTR_LOCAL_STATE_CHANGE)

    A2S(NL80211_ATTR_AP_ISOLATE)

    A2S(NL80211_ATTR_WIPHY_TX_POWER_SETTING)
    A2S(NL80211_ATTR_WIPHY_TX_POWER_LEVEL)

    A2S(NL80211_ATTR_TX_FRAME_TYPES)
    A2S(NL80211_ATTR_RX_FRAME_TYPES)
    A2S(NL80211_ATTR_FRAME_TYPE)

    A2S(NL80211_ATTR_CONTROL_PORT_ETHERTYPE)
    A2S(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT)

    A2S(NL80211_ATTR_SUPPORT_IBSS_RSN)

    A2S(NL80211_ATTR_WIPHY_ANTENNA_TX)
    A2S(NL80211_ATTR_WIPHY_ANTENNA_RX)

    A2S(NL80211_ATTR_MCAST_RATE)

    A2S(NL80211_ATTR_OFFCHANNEL_TX_OK)

    A2S(NL80211_ATTR_BSS_HT_OPMODE)

    A2S(NL80211_ATTR_KEY_DEFAULT_TYPES)

    A2S(NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION)

    A2S(NL80211_ATTR_MESH_SETUP)

    A2S(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX)
    A2S(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX)

    A2S(NL80211_ATTR_SUPPORT_MESH_AUTH)
    A2S(NL80211_ATTR_STA_PLINK_STATE)

    A2S(NL80211_ATTR_WOWLAN_TRIGGERS)
    A2S(NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED)

    A2S(NL80211_ATTR_SCHED_SCAN_INTERVAL)

    A2S(NL80211_ATTR_INTERFACE_COMBINATIONS)
    A2S(NL80211_ATTR_SOFTWARE_IFTYPES)

    A2S(NL80211_ATTR_REKEY_DATA)

    A2S(NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS)
    A2S(NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN)

    A2S(NL80211_ATTR_SCAN_SUPP_RATES)

    A2S(NL80211_ATTR_HIDDEN_SSID)

    A2S(NL80211_ATTR_IE_PROBE_RESP)
    A2S(NL80211_ATTR_IE_ASSOC_RESP)

    A2S(NL80211_ATTR_STA_WME)
    A2S(NL80211_ATTR_SUPPORT_AP_UAPSD)

    A2S(NL80211_ATTR_ROAM_SUPPORT)

    A2S(NL80211_ATTR_SCHED_SCAN_MATCH)
    A2S(NL80211_ATTR_MAX_MATCH_SETS)

    A2S(NL80211_ATTR_PMKSA_CANDIDATE)

    A2S(NL80211_ATTR_TX_NO_CCK_RATE)

    A2S(NL80211_ATTR_TDLS_ACTION)
    A2S(NL80211_ATTR_TDLS_DIALOG_TOKEN)
    A2S(NL80211_ATTR_TDLS_OPERATION)
    A2S(NL80211_ATTR_TDLS_SUPPORT)
    A2S(NL80211_ATTR_TDLS_EXTERNAL_SETUP)

    A2S(NL80211_ATTR_DEVICE_AP_SME)

    A2S(NL80211_ATTR_DONT_WAIT_FOR_ACK)

    A2S(NL80211_ATTR_FEATURE_FLAGS)

    A2S(NL80211_ATTR_PROBE_RESP_OFFLOAD)

    A2S(NL80211_ATTR_PROBE_RESP)

    A2S(NL80211_ATTR_DFS_REGION)

    A2S(NL80211_ATTR_DISABLE_HT)
    A2S(NL80211_ATTR_HT_CAPABILITY_MASK)

    A2S(NL80211_ATTR_NOACK_MAP)
    A2S(NL80211_ATTR_INACTIVITY_TIMEOUT)

    A2S(NL80211_ATTR_RX_SIGNAL_DBM)

    A2S(NL80211_ATTR_BG_SCAN_PERIOD)

    A2S(NL80211_ATTR_WDEV)

    A2S(NL80211_ATTR_USER_REG_HINT_TYPE)

    A2S(NL80211_ATTR_CONN_FAILED_REASON)

    A2S(NL80211_ATTR_AUTH_DATA)

    A2S(NL80211_ATTR_VHT_CAPABILITY)

    A2S(NL80211_ATTR_SCAN_FLAGS)

    A2S(NL80211_ATTR_CHANNEL_WIDTH)
    A2S(NL80211_ATTR_CENTER_FREQ1)
    A2S(NL80211_ATTR_CENTER_FREQ2)

    A2S(NL80211_ATTR_P2P_CTWINDOW)
    A2S(NL80211_ATTR_P2P_OPPPS)

    A2S(NL80211_ATTR_LOCAL_MESH_POWER_MODE)

    A2S(NL80211_ATTR_ACL_POLICY)

    A2S(NL80211_ATTR_MAC_ADDRS)

    A2S(NL80211_ATTR_MAC_ACL_MAX)

    A2S(NL80211_ATTR_RADAR_EVENT)

    A2S(NL80211_ATTR_EXT_CAPA)
    A2S(NL80211_ATTR_EXT_CAPA_MASK)

    A2S(NL80211_ATTR_STA_CAPABILITY)
    A2S(NL80211_ATTR_STA_EXT_CAPABILITY)
    A2S(NL80211_ATTR_PROTOCOL_FEATURES)
    A2S(NL80211_ATTR_SPLIT_WIPHY_DUMP)

    A2S(NL80211_ATTR_DISABLE_VHT)
    A2S(NL80211_ATTR_VHT_CAPABILITY_MASK)

    A2S(NL80211_ATTR_MDID)
    A2S(NL80211_ATTR_IE_RIC)

    A2S(NL80211_ATTR_CRIT_PROT_ID)
    A2S(NL80211_ATTR_MAX_CRIT_PROT_DURATION)

    A2S(NL80211_ATTR_PEER_AID)

    A2S(NL80211_ATTR_COALESCE_RULE)

    A2S(NL80211_ATTR_CH_SWITCH_COUNT)
    A2S(NL80211_ATTR_CH_SWITCH_BLOCK_TX)
    A2S(NL80211_ATTR_CSA_IES)
    A2S(NL80211_ATTR_CSA_C_OFF_BEACON)
    A2S(NL80211_ATTR_CSA_C_OFF_PRESP)

    A2S(NL80211_ATTR_RXMGMT_FLAGS)

    A2S(NL80211_ATTR_STA_SUPPORTED_CHANNELS)

    A2S(NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES)

    A2S(NL80211_ATTR_HANDLE_DFS)

    A2S(NL80211_ATTR_SUPPORT_5_MHZ)
    A2S(NL80211_ATTR_SUPPORT_10_MHZ)

    A2S(NL80211_ATTR_OPMODE_NOTIF)

    A2S(NL80211_ATTR_VENDOR_ID)
    A2S(NL80211_ATTR_VENDOR_SUBCMD)
    A2S(NL80211_ATTR_VENDOR_DATA)
    A2S(NL80211_ATTR_VENDOR_EVENTS)
    A2S(NL80211_ATTR_QOS_MAP)

    A2S(NL80211_ATTR_MAC_HINT)
    A2S(NL80211_ATTR_WIPHY_FREQ_HINT)

    A2S(NL80211_ATTR_MAX_AP_ASSOC_STA)

    A2S(NL80211_ATTR_TDLS_PEER_CAPABILITY)

    A2S(NL80211_ATTR_SOCKET_OWNER)

    A2S(NL80211_ATTR_CSA_C_OFFSETS_TX)
    A2S(NL80211_ATTR_MAX_CSA_COUNTERS)

    A2S(NL80211_ATTR_TDLS_INITIATOR)

    A2S(NL80211_ATTR_USE_RRM)

    A2S(NL80211_ATTR_WIPHY_DYN_ACK)

    A2S(NL80211_ATTR_TSID)
    A2S(NL80211_ATTR_USER_PRIO)
    A2S(NL80211_ATTR_ADMITTED_TIME)

    A2S(NL80211_ATTR_SMPS_MODE)

    A2S(NL80211_ATTR_OPER_CLASS)

    A2S(NL80211_ATTR_MAC_MASK)

    A2S(NL80211_ATTR_WIPHY_SELF_MANAGED_REG)

    A2S(NL80211_ATTR_EXT_FEATURES)

    A2S(NL80211_ATTR_SURVEY_RADIO_STATS)

    A2S(NL80211_ATTR_NETNS_FD)

    A2S(NL80211_ATTR_SCHED_SCAN_DELAY)
    A2S(NL80211_ATTR_REG_INDOOR)

    A2S(NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS)
    A2S(NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL)
    A2S(NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS)
    A2S(NL80211_ATTR_SCHED_SCAN_PLANS)

    A2S(NL80211_ATTR_PBSS)

    A2S(NL80211_ATTR_BSS_SELECT)

    A2S(NL80211_ATTR_STA_SUPPORT_P2P_PS)

    A2S(NL80211_ATTR_PAD)

    A2S(NL80211_ATTR_IFTYPE_EXT_CAPA)

    A2S(NL80211_ATTR_MU_MIMO_GROUP_DATA)
    A2S(NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR)

    A2S(NL80211_ATTR_SCAN_START_TIME_TSF)
    A2S(NL80211_ATTR_SCAN_START_TIME_TSF_BSSID)
    A2S(NL80211_ATTR_MEASUREMENT_DURATION)
    A2S(NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY)

    A2S(NL80211_ATTR_MESH_PEER_AID)

    A2S(NL80211_ATTR_NAN_MASTER_PREF)
    A2S(NL80211_ATTR_BANDS)
    A2S(NL80211_ATTR_NAN_FUNC)
    A2S(NL80211_ATTR_NAN_MATCH)

    A2S(NL80211_ATTR_FILS_KEK)
    A2S(NL80211_ATTR_FILS_NONCES)

    A2S(NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED)

    A2S(NL80211_ATTR_BSSID)

    A2S(NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI)
    A2S(NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST)

    A2S(NL80211_ATTR_TIMEOUT_REASON)

    A2S(NL80211_ATTR_FILS_ERP_USERNAME)
    A2S(NL80211_ATTR_FILS_ERP_REALM)
    A2S(NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM)
    A2S(NL80211_ATTR_FILS_ERP_RRK)
    A2S(NL80211_ATTR_FILS_CACHE_ID)

    A2S(NL80211_ATTR_PMK)

    A2S(NL80211_ATTR_SCHED_SCAN_MULTI)
    A2S(NL80211_ATTR_SCHED_SCAN_MAX_REQS)

    A2S(NL80211_ATTR_WANT_1X_4WAY_HS)
    A2S(NL80211_ATTR_PMKR0_NAME)
    A2S(NL80211_ATTR_PORT_AUTHORIZED)

    A2S(NL80211_ATTR_EXTERNAL_AUTH_ACTION)
    A2S(NL80211_ATTR_EXTERNAL_AUTH_SUPPORT)

    A2S(NL80211_ATTR_NSS)
    A2S(NL80211_ATTR_ACK_SIGNAL)

    A2S(NL80211_ATTR_CONTROL_PORT_OVER_NL80211)

    A2S(NL80211_ATTR_TXQ_STATS)
    A2S(NL80211_ATTR_TXQ_LIMIT)
    A2S(NL80211_ATTR_TXQ_MEMORY_LIMIT)
    A2S(NL80211_ATTR_TXQ_QUANTUM)

    default:
        return "NL80211_ATTRIB_UNKNOWN";

    }
#undef A2S
}

/*
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 * Licensed under the BSD-3 License
*/
const char *nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
    switch (cmd) {
    C2S(NL80211_CMD_UNSPEC)
    C2S(NL80211_CMD_GET_WIPHY)
    C2S(NL80211_CMD_SET_WIPHY)
    C2S(NL80211_CMD_NEW_WIPHY)
    C2S(NL80211_CMD_DEL_WIPHY)
    C2S(NL80211_CMD_GET_INTERFACE)
    C2S(NL80211_CMD_SET_INTERFACE)
    C2S(NL80211_CMD_NEW_INTERFACE)
    C2S(NL80211_CMD_DEL_INTERFACE)
    C2S(NL80211_CMD_GET_KEY)
    C2S(NL80211_CMD_SET_KEY)
    C2S(NL80211_CMD_NEW_KEY)
    C2S(NL80211_CMD_DEL_KEY)
    C2S(NL80211_CMD_GET_BEACON)
    C2S(NL80211_CMD_SET_BEACON)
    C2S(NL80211_CMD_START_AP)
    C2S(NL80211_CMD_STOP_AP)
    C2S(NL80211_CMD_GET_STATION)
    C2S(NL80211_CMD_SET_STATION)
    C2S(NL80211_CMD_NEW_STATION)
    C2S(NL80211_CMD_DEL_STATION)
    C2S(NL80211_CMD_GET_MPATH)
    C2S(NL80211_CMD_SET_MPATH)
    C2S(NL80211_CMD_NEW_MPATH)
    C2S(NL80211_CMD_DEL_MPATH)
    C2S(NL80211_CMD_SET_BSS)
    C2S(NL80211_CMD_SET_REG)
    C2S(NL80211_CMD_REQ_SET_REG)
    C2S(NL80211_CMD_GET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
    C2S(NL80211_CMD_GET_REG)
    C2S(NL80211_CMD_GET_SCAN)
    C2S(NL80211_CMD_TRIGGER_SCAN)
    C2S(NL80211_CMD_NEW_SCAN_RESULTS)
    C2S(NL80211_CMD_SCAN_ABORTED)
    C2S(NL80211_CMD_REG_CHANGE)
    C2S(NL80211_CMD_AUTHENTICATE)
    C2S(NL80211_CMD_ASSOCIATE)
    C2S(NL80211_CMD_DEAUTHENTICATE)
    C2S(NL80211_CMD_DISASSOCIATE)
    C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
    C2S(NL80211_CMD_REG_BEACON_HINT)
    C2S(NL80211_CMD_JOIN_IBSS)
    C2S(NL80211_CMD_LEAVE_IBSS)
    C2S(NL80211_CMD_TESTMODE)
    C2S(NL80211_CMD_CONNECT)
    C2S(NL80211_CMD_ROAM)
    C2S(NL80211_CMD_DISCONNECT)
    C2S(NL80211_CMD_SET_WIPHY_NETNS)
    C2S(NL80211_CMD_GET_SURVEY)
    C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
    C2S(NL80211_CMD_SET_PMKSA)
    C2S(NL80211_CMD_DEL_PMKSA)
    C2S(NL80211_CMD_FLUSH_PMKSA)
    C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
    C2S(NL80211_CMD_REGISTER_FRAME)
    C2S(NL80211_CMD_FRAME)
    C2S(NL80211_CMD_FRAME_TX_STATUS)
    C2S(NL80211_CMD_SET_POWER_SAVE)
    C2S(NL80211_CMD_GET_POWER_SAVE)
    C2S(NL80211_CMD_SET_CQM)
    C2S(NL80211_CMD_NOTIFY_CQM)
    C2S(NL80211_CMD_SET_CHANNEL)
    C2S(NL80211_CMD_SET_WDS_PEER)
    C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
    C2S(NL80211_CMD_JOIN_MESH)
    C2S(NL80211_CMD_LEAVE_MESH)
    C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
    C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
    C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
    C2S(NL80211_CMD_GET_WOWLAN)
    C2S(NL80211_CMD_SET_WOWLAN)
    C2S(NL80211_CMD_START_SCHED_SCAN)
    C2S(NL80211_CMD_STOP_SCHED_SCAN)
    C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
    C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
    C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
    C2S(NL80211_CMD_PMKSA_CANDIDATE)
    C2S(NL80211_CMD_TDLS_OPER)
    C2S(NL80211_CMD_TDLS_MGMT)
    C2S(NL80211_CMD_UNEXPECTED_FRAME)
    C2S(NL80211_CMD_PROBE_CLIENT)
    C2S(NL80211_CMD_REGISTER_BEACONS)
    C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
    C2S(NL80211_CMD_SET_NOACK_MAP)
    C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
    C2S(NL80211_CMD_START_P2P_DEVICE)
    C2S(NL80211_CMD_STOP_P2P_DEVICE)
    C2S(NL80211_CMD_CONN_FAILED)
    C2S(NL80211_CMD_SET_MCAST_RATE)
    C2S(NL80211_CMD_SET_MAC_ACL)
    C2S(NL80211_CMD_RADAR_DETECT)
    C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
    C2S(NL80211_CMD_UPDATE_FT_IES)
    C2S(NL80211_CMD_FT_EVENT)
    C2S(NL80211_CMD_CRIT_PROTOCOL_START)
    C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
    C2S(NL80211_CMD_GET_COALESCE)
    C2S(NL80211_CMD_SET_COALESCE)
    C2S(NL80211_CMD_CHANNEL_SWITCH)
    C2S(NL80211_CMD_VENDOR)
    C2S(NL80211_CMD_SET_QOS_MAP)
    C2S(NL80211_CMD_ADD_TX_TS)
    C2S(NL80211_CMD_DEL_TX_TS)
    C2S(NL80211_CMD_WIPHY_REG_CHANGE)
    C2S(NL80211_CMD_PORT_AUTHORIZED)
    C2S(NL80211_CMD_EXTERNAL_AUTH)
    C2S(NL80211_CMD_STA_OPMODE_CHANGED)
    C2S(NL80211_CMD_CONTROL_PORT_FRAME)
    default:
        return "NL80211_CMD_UNKNOWN";
    }
#undef C2S
}

void print_attributes(char *cmd, struct nlattr *tb[])
{
    unsigned int i;
    wifi_hal_dbg_print("\n%s attributes:\n", cmd);
    for (i = 0; i < NL80211_ATTR_MAX; i++) {
        if (tb[i] != NULL) {
            wifi_hal_dbg_print("%s\t", nl80211_attribute_to_string(nla_type(tb[i])));
        }
    }
    wifi_hal_dbg_print("\n\n");
}

void print_supported_commands(char *cmd, struct nlattr *tb)
{
    unsigned int i;
    struct nlattr *nl_cmd;

    if (tb != NULL) {
        wifi_hal_dbg_print("\n%s commands:\n", cmd);
        nla_for_each_nested(nl_cmd, tb, i) {
            wifi_hal_dbg_print("%s\t", nl80211_command_to_string(nla_get_u32(nl_cmd)));
        }
        wifi_hal_dbg_print("\n\n");
    }
}

char *get_wifi_drv_name()
{
    return driver_info.driver_name;
}

wifi_device_info_t get_device_info_details()
{
    return driver_info.device_info;
}
platform_pre_init_t	get_platform_pre_init_fn()
{
    return driver_info.platform_pre_init_fn;
}

platform_post_init_t 	get_platform_post_init_fn()
{
    return driver_info.platform_post_init_fn;
}

platform_ssid_default_t get_platform_ssid_default_fn()
{
   return driver_info.platform_ssid_default_fn;
}

platform_keypassphrase_default_t get_platform_keypassphrase_default_fn()
{
   return driver_info.platform_keypassphrase_default_fn;
}
platform_radius_key_default_t get_platform_radius_key_default_fn()
{
   return driver_info.platform_radius_key_default_fn;
}

platform_wps_pin_default_t get_platform_wps_pin_default_fn()
{
   return driver_info.platform_wps_pin_default_fn;
}

platform_country_code_default_t get_platform_country_code_default_fn()
{
    return driver_info.platform_country_code_default_fn;
}

platform_set_radio_params_t	get_platform_set_radio_fn()
{
    return driver_info.platform_set_radio_fn;
}

platform_create_vap_t	get_platform_create_vap_fn()
{
    return driver_info.platform_create_vap_fn;
}

platform_set_radio_pre_init_t get_platform_set_radio_pre_init_fn()
{
    return driver_info.platform_set_radio_pre_init_fn;
}

bool lsmod_by_name(const char *name)
{
    FILE *fp = NULL;
    char line[4096];

    if ((fp = fopen("/proc/modules", "r")) == NULL) {
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name) != NULL) {
            fclose(fp);
            return true;
        }
    }

    fclose(fp);

    return false;
}
