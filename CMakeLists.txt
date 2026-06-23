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
    src/reporter.cpp
    src/cli_parser.cpp
)

if(WIN32)
    target_link_libraries(netpulse ws2_32)
endif()

if(MSVC)
    # Microsoft compiler uses /W4 for high warnings
    add_compile_options(/W4)
else()
    # GCC/Clang use -Wall -Wextra
    add_compile_options(-Wall -Wextra)
endif()

# Note: Set CMAKE_BUILD_TYPE to Debug or Release when configuring the project
