cmake_minimum_required(VERSION 3.12)
project(netpulse VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include directories
include_directories(./include)

# Target executable and its source files
add_executable(netpulse
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/classifier.cpp
)

if(WIN32)
    target_link_libraries(netpulse ws2_32)
endif()
