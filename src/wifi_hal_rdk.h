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

#ifndef _WIFI_HAL_RDK_H_
#define _WIFI_HAL_RDK_H_

#include "wifi_hal.h"

typedef struct
{
    unsigned char cat;
    unsigned char action;
} __attribute__((packed)) wifi_actionFrameHdr_t;

typedef wifi_actionFrameHdr_t wifi_publicActionFrameHdr_t;

typedef struct
{
    unsigned char query_rsp_info;
    unsigned char adv_proto_id;
    unsigned char len;
    unsigned char oui[0];
} __attribute__((packed)) wifi_advertisementProtoTuple_t;

typedef struct
{
    unsigned char id;
    unsigned char len;
    wifi_advertisementProtoTuple_t proto_tuple;
} __attribute__((packed)) wifi_advertisementProtoElement_t;

typedef struct
{
    unsigned char token;
    wifi_advertisementProtoElement_t proto_elem;
} __attribute__((packed)) wifi_gasInitialRequestFrame_t;

typedef struct
{
    unsigned char token;
    unsigned short status;
    unsigned short comeback_delay;
    wifi_advertisementProtoElement_t proto_elem;
} __attribute__((packed)) wifi_gasInitialResponseFrame_t;

/* DPP structure definitions */
typedef struct
{
    unsigned char oui[3];
    unsigned char oui_type;
} __attribute__((packed)) wifi_dppOUI;

typedef struct
{
    wifi_dppOUI dpp_oui;
    unsigned char crypto;
    unsigned char frame_type;
    unsigned char attrib[0];
} __attribute__((packed)) wifi_dppPublicActionFrameBody_t;

typedef struct
{
    wifi_publicActionFrameHdr_t public_action_hdr;
    wifi_dppPublicActionFrameBody_t public_action_body;
} __attribute__((packed)) wifi_dppPublicActionFrame_t;

typedef struct
{
    wifi_publicActionFrameHdr_t public_action_hdr;
    wifi_gasInitialResponseFrame_t gas_resp_body;
    wifi_dppOUI dpp_oui;
    unsigned char dpp_proto;
    unsigned short rsp_len;
    unsigned char rsp_body[0];
} __attribute__((packed)) wifi_dppConfigResponseFrame_t;
/* //END OF DPP structure definitions */

/* ANQP structure definitions */
typedef struct
{
    unsigned char query_rsp_info;
    unsigned char adv_proto_id;
} __attribute__((packed)) wifi_AnqpAdvertisementProtoTuple_t;

typedef struct
{
    unsigned char id;
    unsigned char len;
    wifi_AnqpAdvertisementProtoTuple_t proto_tuple;
} __attribute__((packed)) wifi_AnqpAdvertisementProtoElement_t;

typedef struct
{
    unsigned char token;
    unsigned short status;
    unsigned short comeback_delay;
    wifi_AnqpAdvertisementProtoElement_t proto_elem;
} __attribute__((packed)) wifi_gasAnqpInitialResponseFrame_t;

typedef struct
{
    wifi_publicActionFrameHdr_t public_action_hdr;
    wifi_gasAnqpInitialResponseFrame_t gas_resp_body;
    unsigned short rsp_len;
    unsigned char rsp_body[0];
} __attribute__((packed)) wifi_anqpResponseFrame_t;

typedef struct
{
    unsigned short info_id;
    unsigned short len;
    unsigned char info[0];
} __attribute__((packed)) wifi_anqp_element_format_t;

typedef struct
{
    unsigned short info_id;
    unsigned short len;
    unsigned char oi[3];
    unsigned char type;
    unsigned char subtype;
    unsigned char reserved;
    unsigned char payload[0];
} __attribute__((packed)) wifi_hs_2_anqp_element_format_t;
/* //END OF ANQP structure definitions */

typedef struct _wifi_HS2Settings_t
{
    BOOL countryIe;
    BOOL layer2TIF;
    BOOL downStreamGroupAddress;
    BOOL bssLoad;
    BOOL proxyArp;
}wifi_HS2Settings_t;

//Eap Stats
typedef struct _wifi_EapStats_t{    // Passpoint stats defined rdkb-1317
    unsigned int EAPOLStartSuccess;
    unsigned int EAPOLStartFailed;
    unsigned int EAPOLStartTimeouts;
    unsigned int EAPOLStartRetries;
    unsigned int EAPOLSuccessSent;
    unsigned int EAPFailedSent;
} wifi_EapStats_t;

#define DPP_SUB_AUTH_REQUEST 0
#define DPP_SUB_AUTH_RESPONSE 1
#define DPP_SUB_AUTH_CONFIRM 2
/* RESERVED 3-4 */
#define DPP_SUB_PEER_DISCOVER_REQ 5
#define DPP_SUB_PEER_DISCOVER_RESP 6
#define PKEX_SUB_EXCH_REQ 7
#define PKEX_SUB_EXCH_RESP 8
#define PKEX_SUB_COM_REV_REQ 9
#define PKEX_SUB_COM_REV_RESP 10
/* RESERVED 11-255 */

#define DPP_OUI_TYPE  0x1a // OUI Type
#define DPP_CONFPROTO 0x01 // denoting the DPP Configuration protocol

#define STATUS_OK 0
#define STATUS_NOT_COMPATIBLE 1
#define STATUS_AUTH_FAILURE 2
#define STATUS_DECRYPT_FAILURE 3
#define STATUS_CONFIGURE_FAILURE 5
#define STATUS_RESPONSE_PENDING 6
#define STATUS_INVALID_CONNECTOR 7

typedef enum
{
    wifi_dpp_attrib_id_status	= 	0x1000,
    wifi_dpp_attrib_id_initiator_boot_hash,
    wifi_dpp_attrib_id_responder_boot_hash,
    wifi_dpp_attrib_id_initiator_protocol_key,
    wifi_dpp_attrib_id_wrapped_data,
    wifi_dpp_attrib_id_initiator_nonce,
    wifi_dpp_attrib_id_initiator_cap,
    wifi_dpp_attrib_id_responder_nonce,
    wifi_dpp_attrib_id_responder_cap,
    wifi_dpp_attrib_id_responder_protocol_key,
    wifi_dpp_attrib_id_initiator_auth_tag,
    wifi_dpp_attrib_id_responder_auth_tag,
    wifi_dpp_attrib_id_config_object,
    wifi_dpp_attrib_id_connector,
    wifi_dpp_attrib_id_config_req_object,
    wifi_dpp_attrib_id_bootstrap_key,
    wifi_dpp_attrib_id_reserved_1,
    wifi_dpp_attrib_id_reserved_2,
    wifi_dpp_attrib_id_finite_cyclic_group,
    wifi_dpp_attrib_id_encrypted_key,
    wifi_dpp_attrib_id_enrollee_nonce,
    wifi_dpp_attrib_id_code_id,
    wifi_dpp_attrib_id_transaction_id,
    wifi_dpp_attrib_id_bootstrapping_info,
    wifi_dpp_attrib_id_channel,
    wifi_dpp_attrib_id_proto_version,
    wifi_dpp_attrib_id_enveloped_data,
    wifi_dpp_attrib_id_send_conn_status,
    wifi_dpp_attrib_id_conn_status,
    wifi_dpp_attrib_id_reconfig_flags,
    wifi_dpp_attrib_id_C_sign_key_hash,
} wifi_dpp_attrib_id_t;

#define DPP_STATUS 0x1000
#define INITIATOR_BOOT_HASH 0x1001
#define RESPONDER_BOOT_HASH 0x1002
#define INITIATOR_PROTOCOL_KEY 0x1003
#define WRAPPED_DATA 0x1004
#define INITIATOR_NONCE 0x1005
#define INITIATOR_CAPABILITIES 0x1006
#define RESPONDER_NONCE 0x1007
#define RESPONDER_CAPABILITIES 0x1008
#define RESPONDER_PROTOCOL_KEY 0x1009
#define INITIATOR_AUTH_TAG 0x100a
#define RESPONDER_AUTH_TAG 0x100b
#define CONFIGURATION_OBJECT 0x100c
#define CONNECTOR 0x100d
#define CONFIG_ATTRIBUTES_OBJECT 0x100e
#define BOOTSTRAP_KEY 0x100f
#define HASH_OF_PEER_PK 0x1010
#define HASH_OF_DEVICE_NK 0x1011
#define FINITE_CYCLIC_GROUP 0x1012
#define ENCRYPTED_KEY 0x1013
#define ENROLLEE_NONCE 0x1014
#define CODE_IDENTIFIER 0x1015
#define TRANSACTION_IDENTIFIER 0x1016
#define CHANGE_CHANNEL 0x1018

typedef struct
{
    unsigned short type;
    unsigned short length;
    unsigned char value[0];
} __attribute__((packed)) wifi_tlv_t;

typedef enum
{
    wifi_adv_proto_id_anqp,
    wifi_adv_proto_id_mih_info_svc,
    wifi_adv_proto_id_mih_cmd_evt_svc_disc,
    wifi_adv_proto_id_eas,
    wifi_adv_proto_id_rlqp,
    wifi_adv_proto_id_vendor_specific = 221,
} wifi_adv_proto_id_t;

typedef enum
{
    wifi_action_frame_type_spectrum_mgmt,
    wifi_action_frame_type_qos,
    wifi_action_frame_type_dls,
    wifi_action_frame_type_block_ack,
    wifi_action_frame_type_public,
    wifi_action_frame_type_radio_msmt,
    wifi_action_frame_type_fast_bss,
    wifi_action_frame_type_ht,
} wifi_action_frame_type_t;

typedef enum
{
    wifi_public_action_type_bss_coex,
    wifi_public_action_type_dse_enable,
    wifi_public_action_type_dse_disable,
    wifi_public_action_type_dse_loc_announce,
    wifi_public_action_type_ext_channel_switch,
    wifi_public_action_type_dse_msmt_req,
    wifi_public_action_type_dse_msmt_rep,
    wifi_public_action_type_msmt_pilot,
    wifi_public_action_type_dse_pwr,
    wifi_public_action_type_vendor,
    wifi_public_action_type_gas_init_req,
    wifi_public_action_type_gas_init_rsp,
    wifi_public_action_type_gas_comeback_req,
    wifi_public_action_type_gas_comeback_rsp,
    wifi_public_action_type_tdls_disc_rsp,
    wifi_public_action_type_loc_track_not,
} wifi_public_action_type_t;

typedef enum {
    wifi_test_command_id_mgmt = 0x1010,
    wifi_test_command_id_action,
    wifi_test_command_id_probe_req,
    wifi_test_command_id_probe_rsp,
    wifi_test_command_id_assoc_req,
    wifi_test_command_id_assoc_rsp,
    wifi_test_command_id_auth,
    wifi_test_command_id_deauth,
    wifi_test_command_id_data = 0x1050,
    wifi_test_command_id_8021x,
    wifi_test_command_id_ctl = 0x10a0,
    wifi_test_command_id_chirp,
    wifi_test_command_id_anqp,
    wifi_test_command_id_reconf_auth_resp,
} wifi_test_command_id_t;

typedef enum
{
	wifi_test_attrib_cmd,
	wifi_test_attrib_vap_name,
	wifi_test_attrib_sta_mac,
	wifi_test_attrib_direction,
	wifi_test_attrib_raw
} wifi_test_attrib_t;

struct ieee80211_radiotap_header {
    unsigned char   it_version;     /* set to 0 */
    unsigned char   it_pad;
    unsigned short  it_len;         /* entire length */
    unsigned int    it_present;     /* fields present */
} __attribute__((__packed__));

typedef struct {
    unsigned char   pad[8];
    unsigned int    caplen;
    unsigned int    len;
} __attribute__((__packed__)) wireshark_pkthdr_t;

typedef struct {
    unsigned int    block_type;
    unsigned int    block_len;
    unsigned int    magic;
    unsigned short  major;
    unsigned short  minor;
} __attribute__((__packed__)) section_header_block_t;

typedef struct {
    unsigned int    block_type;
    unsigned int    block_len;
    unsigned short  link_type;
    unsigned short  reserved;
    unsigned int    snap_len;
} __attribute__((__packed__)) interface_description_block_t;

typedef struct {
    unsigned int    block_type;
    unsigned int    block_len;
    unsigned int    intf_id;
    unsigned int    time_high;
    unsigned int    time_low;
    unsigned int    caplen;
    unsigned int    len;
} __attribute__((__packed__)) enhanced_packet_block_t;

typedef struct {
    unsigned char   ccmp[8];
} __attribute__((__packed__)) ccmp_hdr_t;

typedef struct {
    unsigned char   dsap;
    unsigned char   ssap;
    unsigned char   control;
    unsigned char   oui[3];
    unsigned char   type[2];
} __attribute__((__packed__)) llc_hdr_t;

typedef struct {
    char            interface_name[32];
    unsigned char   mac[6];
    bool            uplink_downlink;
    unsigned int    num_commands;
    wifi_test_command_id_t cmd[10];
    unsigned int    first_frame_num;
    unsigned int    last_frame_num;
    char            cap_file_name[128];
} frame_test_arg_t;

wifi_tlv_t *get_tlv(unsigned char *buff, unsigned short attrib, unsigned short len);
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val);

typedef enum
{
    wifi_gas_status_success = 0,
    wifi_gas_advertisement_protocol_not_supported = 59,
    wifi_no_outstanding_gas_request = 60,
    wifi_gas_response_not_received_from_server = 61,
    wifi_gas_query_timeout = 62,
    wifi_gas_query_response_too_large = 63
} wifi_gas_status_code_t;

#endif
