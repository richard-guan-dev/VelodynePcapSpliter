#include "velo_pcap_split.h"
#include <stdlib.h>
#include <io.h>
#include <iostream>
#include <string>
#include <sstream>
#include "file_raii.hpp"
#include "buffer_raii.hpp"
#include "pcap.h"

namespace hadmap {

VeloPcapSplit::VeloPcapSplit() {
}

VeloPcapSplit::VeloPcapSplit(const char* input_filepath,
                             const char* output_filepath) : _in_file(nullptr), _input_filepath(input_filepath),
    _output_filepath(output_filepath) {

    if (_access(input_filepath, 0) != -1) {
        _in_file = fopen(input_filepath, "rb");
    }
}

VeloPcapSplit::~VeloPcapSplit() {
}

void VeloPcapSplit::do_split() {
    if (_in_file == nullptr) {
        return;
    }

    static const size_t BUFFER_SIZE = 1024 * 1024 * 10;
    static const size_t BODY_SIZE = 1024 * 1024 * 10;
    static const int PCAP_MAGIC = 0xA1B2C3D4;
    static const int UDP_PROTOCAL = 0x11;
    static const size_t FILE_MAX_SIZE = 1024 * 1024;

    char* buff = new char[BUFFER_SIZE];

    BufferRAII buff_raii(&buff);
    PcapHeader file_header;

    fread(&file_header, sizeof(PcapHeader), 1, _in_file);

    if (file_header.magic != PCAP_MAGIC) {
        std::cerr << "file format error" << std::endl;

        return;
    }

    size_t totalsize = 0;
    int counter = 0;

    FILE* outfile = NULL;

    std::string output_filepath = "";
    output_filepath = _output_filepath + "/";
    std::stringstream ss;
    ss << output_filepath;
    ss << counter;
    ss << ".pcap";

    ss >> output_filepath;

    if ((outfile = fopen(output_filepath.c_str(), "wb")) == NULL) {
        std::cerr << "cant write" << std::endl;

        return;
    }

    FileRAII o_raii(outfile);

    fwrite(&file_header, sizeof(PcapHeader), 1, outfile);

    while (!feof(_in_file)) {
        PktHeader pkt_header;

        fread(&pkt_header, sizeof(PktHeader), 1, _in_file);
        fread(buff, pkt_header.len, 1, _in_file);

        Ethernet eth_header;
        IpHeader ip_header;
        UdpHeader udp_header;

        memcpy(&eth_header, buff, sizeof(Ethernet));
        memcpy(&ip_header, buff + sizeof(Ethernet), sizeof(IpHeader));
        memcpy(&udp_header, buff + sizeof(Ethernet) + sizeof(IpHeader), sizeof(UdpHeader));

        if (ip_header.protocol != UDP_PROTOCAL) {
            std::cerr << "wrong protocol" << std::endl;

            return;
        }

        u_int16 udp_body_length = htons(udp_header.length);
        u_int16 udp_dst_port = htons(udp_header.dst_port);

        if (totalsize > FILE_MAX_SIZE && udp_dst_port == 8308) {
            fclose(outfile);
            outfile = NULL;

            output_filepath = _output_filepath + "/";
            std::stringstream ss;
            ss << output_filepath;
            ss << ++counter;
            ss << ".pcap";

            ss >> output_filepath;

            if ((outfile = fopen(output_filepath.c_str(), "wb")) == NULL) {
                std::cerr << "not open" << std::endl;

                return;
            }

            o_raii.file(outfile);

            totalsize = 0;
            fwrite(&file_header, sizeof(PcapHeader), 1, outfile);

        }

        fwrite(&pkt_header, sizeof(PktHeader), 1, outfile);
        fwrite(buff, pkt_header.len, 1, outfile);

        totalsize += pkt_header.len;
    }
}
}