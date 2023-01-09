#ifndef BEACON_H
#define BEACON_H
#include <stdint.h>

struct radiotap_header {
    uint8_t     version;     /* set to 0 */
    uint8_t     pad;
    uint16_t    len;         /* entire length */
    uint32_t    present;     /* fields present */
} __attribute__((__packed__));

struct beacon_header{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t dhost[6];  //목적지 주소
    uint8_t shost[6];  //출발지 주소
    uint8_t bssid[6];
    uint16_t squence_control;
} __attribute__ ((__packed__));

struct fixed_parameters{
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capacity_info;
} __attribute__ ((__packed__));

struct tag_parameter{
    uint8_t element_id;
    uint8_t len;
} __attribute__ ((__packed__));

struct tag_SSID_parameter{
    uint8_t element_id;
    uint8_t len;
    uint8_t ssid[32];
} __attribute__ ((__packed__));

struct tag_DS_parameter{
    uint8_t number;
    uint8_t len;
    uint8_t channel;
} __attribute__ ((__packed__));

int radiotap_length(struct radiotap_header *radiotap_header);
int beacon_header_length(struct beacon_header *beacon_header);
int tag_parameter_number(struct tag_parameter *tag_parameter);
int tag_parameter_length(struct tag_parameter *tag_parameter);
int SSID_parameter(struct tag_SSID_parameter *tag_SSID_parameter);
int DS_parameter(struct tag_DS_parameter *tag_DS_parameter);

#endif // BEACON_H
