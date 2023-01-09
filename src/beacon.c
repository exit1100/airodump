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

int tag_parameter_number(struct tag_parameter *tag_parameter){
    unsigned int type = tag_parameter->element_id;
    return type;
}

int tag_parameter_length(struct tag_parameter *tag_parameter){
    unsigned int len = tag_parameter->len;
    return len;
}
