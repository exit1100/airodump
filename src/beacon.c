#include <stdio.h>
#include "beacon.h"

int radiotap_length(struct radiotap_header *radiotap_header){
    unsigned int len = radiotap_header->len;
    return len;
}

int beacon_header_length(struct beacon_header *beacon_header){
    unsigned int frameControl = htons(beacon_header->frame_control);
    return frameControl;
}

int fixed_parameters_length(struct fixed_parameters *fixed_parameters){
}

int tag_parameter_number(struct tag_parameter *tag_parameter){
    unsigned int type = tag_parameter->element_id;
    return type;
}

int tag_parameter_length(struct tag_parameter *tag_parameter){
    unsigned int len = tag_parameter->len;
    return len;
}



int dump_SSID_parameter(struct tag_SSID_parameter *tag_SSID_parameter){
    unsigned int len = tag_SSID_parameter->len;
    return len;
}

int dump_supported_rates(struct tag_supported_rates *tag_supported_rates){
    unsigned int len = tag_supported_rates->len;
    return len;
}

int dump_DS_parameter(struct tag_DS_parameter *tag_DS_parameter){
    unsigned int len = tag_DS_parameter->len;
    return len;
}
