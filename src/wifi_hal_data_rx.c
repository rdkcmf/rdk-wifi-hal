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
#include "wifi_hal_rdk_framework.h"
#include "wifi_hal.h"
#include "wifi_hal_rdk.h"
#include "ieee80211.h"

int handle_8021x_frame(INT ap_index, mac_address_t sta_mac, unsigned char *frame, UINT len, wifi_direction_t dir)
{
       llc_hdr_t *llc_hdr;
       struct ieee80211_frame *ieeehdr;
       wifi_8021x_frame_t *data;
       wifi_eap_frame_t *eap;
       wifi_eapol_key_frame_t  *key;
       char    msg[32];
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();
       if (callbacks == NULL) {
               return -1;
       }

       ieeehdr = (struct ieee80211_frame *)frame;

    if (IEEE80211_IS_DSTODS(ieeehdr)) {
        // the header has 4 MAC addresses because this is DS to DS
        data = (wifi_8021x_frame_t *)((unsigned char *)frame + sizeof(struct ieee80211_frame_addr4));
        len -= sizeof(struct ieee80211_frame_addr4);
    } else {
        data = (wifi_8021x_frame_t *)((unsigned char *)frame + sizeof(struct ieee80211_frame));
        len -= sizeof(struct ieee80211_frame);
    }
   
    if (IEEE80211_IS_QOSDATA(ieeehdr)) {
        data = (wifi_8021x_frame_t *)((unsigned char *)data + sizeof(struct ieee80211_qoscntl));
        len -= sizeof(struct ieee80211_qoscntl);
    }
   
    if ((ieeehdr)->i_fc[1] & IEEE80211_FC1_PROTECTED) {
        data = (wifi_8021x_frame_t *)((unsigned char *)data + sizeof(ccmp_hdr_t));
        len -= sizeof(ccmp_hdr_t);
    } else {
        // if this is plain text and length of the data is more than LLC check if there is an LLC header
        if (len > sizeof(llc_hdr_t)) {
            llc_hdr = (llc_hdr_t *)data;
            if ((llc_hdr->dsap == 0xaa) && (llc_hdr->ssap == 0xaa)) {
                if ((llc_hdr->type[0] == 0x88) && (llc_hdr->type[1] == 0x8e)) {
                    data = (wifi_8021x_frame_t *)((unsigned char *)data + sizeof(llc_hdr_t));
                    len -= sizeof(llc_hdr_t);
                }
            }
        }
    }


#ifdef DEBUG_8021X

       switch (data->type) {
               case wifi_eapol_type_eap_packet:
                       eap = (wifi_eap_frame_t *)data->data;

                       if (eap->code == 1) {
                               strcpy(msg, "request");
                       } else if (eap->code == 2) {
                               strcpy(msg, "response");
                       } else if (eap->code == 3) {
                               strcpy(msg, "success");
                       } else if (eap->code == 4) {
                               strcpy(msg, "failure");
                       }

                       printf("%s:%d: Received eap %s  id:%d\n", __func__, __LINE__, msg, eap->id);
                       break;
               
               case wifi_eapol_type_eapol_start:
                       break;
               
               case wifi_eapol_type_eapol_logoff:
                       break;
               
               case wifi_eapol_type_eapol_key:
                       key = (wifi_eapol_key_frame_t *)data->data;
                       if (KEY_MSG_1_OF_4(key)) {
                               strcpy(msg, "Message 1 of 4");
                       } else if (KEY_MSG_2_OF_4(key)) {
                               strcpy(msg, "Message 2 of 4");
                       } else if (KEY_MSG_3_OF_4(key)) {
                               strcpy(msg, "Message 3 of 4");
                       } else if (KEY_MSG_4_OF_4(key)) {
                               strcpy(msg, "Message 4 of 4");
                       }
                       
                       printf("%s:%d: Received eapol key packet: %s\n", __func__, __LINE__, msg);
                       break;
       }
#else
       (void)(eap);
       (void)(key);
       (void)(msg); //unused variables
#endif

       if (dir == wifi_direction_downlink) {
               if (callbacks->eapol_frame_tx_callback != NULL) {
                       callbacks->eapol_frame_tx_callback(ap_index, sta_mac, data->type, data->data, len - sizeof(wifi_8021x_frame_t));
               }
       } else if (dir == wifi_direction_uplink) {
               if (callbacks->eapol_frame_rx_callback != NULL) {
                       callbacks->eapol_frame_rx_callback(ap_index, sta_mac, data->type, data->data, len - sizeof(wifi_8021x_frame_t));        
               }
       }

       return RETURN_OK;
}

int data_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_dataFrameType_t type, wifi_direction_t dir)
{
    if (type == WIFI_DATA_FRAME_TYPE_8021x) {
               handle_8021x_frame(ap_index, sta_mac, frame, len, dir); 
    }
    return RETURN_OK;
}

void wifi_8021x_data_tx_callback_register(wifi_sent8021xFrame_callback func)
{
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();

       callbacks->eapol_frame_tx_callback = func;
}

void wifi_8021x_data_rx_callback_register(wifi_received8021xFrame_callback func)
{
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();

       callbacks->eapol_frame_rx_callback = func;
}
