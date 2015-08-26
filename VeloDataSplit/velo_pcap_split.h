#pragma once
#include <stdio.h>
#include <string>

#ifndef _WIN64
#include <arpa/inet.h>¡¡
#endif // _WIN64


#include "pcap.h"
namespace hadmap {

class VeloPcapSplit {
public:
    VeloPcapSplit(const char* input_filepath, const char* output_filepath);
    ~VeloPcapSplit();

    void do_split();
private:
    VeloPcapSplit();

    std::string _input_filepath;
    std::string _output_filepath;
    FILE* _in_file;

};

#ifdef _WIN64
// _WIN64
static inline u_int16 htons(u_int16 src) {
    u_int8 temp = src >> 8;
    src <<= 8;
    src += temp;
    return src;
}
#endif
}

