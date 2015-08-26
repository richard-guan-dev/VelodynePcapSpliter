#include <iostream>
#include "gflags/gflags.h"
#include "boost/filesystem/path.hpp"
#include "boost/filesystem.hpp"
#include "velo_pcap_split.h"

DEFINE_string(input_file, "./00.pcap", "input pcap file");
DEFINE_string(output_folder, "./output", "output pcap folder");

int main(int argc, char** argv) {
    google::ParseCommandLineFlags(&argc, &argv, true);

    std::cout << FLAGS_input_file << " " << FLAGS_output_folder << std::endl;

    boost::filesystem::path p(FLAGS_output_folder);

    if (!boost::filesystem::is_directory(p) && !boost::filesystem::exists(p)) {
        if (!boost::filesystem::create_directories(p)) {
            std::cerr << "create output folder failed";

            return -1;
        }
    }

    hadmap::VeloPcapSplit spliter(FLAGS_input_file.c_str(), FLAGS_output_folder.c_str());
    spliter.do_split();

    return 0;
}