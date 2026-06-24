cmake_minimum_required(VERSION 3.12)
project(netpulse VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 1. Global Project Include Directories
include_directories(./include)

# 2. Windows-Specific SDK Paths & Headers Configuration
if(WIN32)
    # Define the Npcap SDK path (Note: CMake requires forward slashes '/')
    set(NPCAP_SDK_DIR "D:/Dev Tools/npcap-sdk-1.16" CACHE PATH "Path to Npcap SDK")
    
    message(STATUS "Configuring build for Windows. Using Npcap SDK: ${NPCAP_SDK_DIR}")
    
    # Inject the Npcap SDK include directory so #include <pcap.h> works on Windows
    include_directories(${NPCAP_SDK_DIR}/Include)
    
    # Locate wpcap.lib using the SDK paths as a target hint
    find_library(PCAP_LIBRARY 
        NAMES wpcap 
        HINTS "${NPCAP_SDK_DIR}/Lib/x64" "${NPCAP_SDK_DIR}/Lib"
    )
else()
    message(STATUS "Configuring build for Unix-like system (Linux/macOS).")
    
    # On Linux/macOS, libpcap is in standard system locations
    find_library(PCAP_LIBRARY NAMES pcap)
endif()

# 3. Define Executable# Target executable and its source files
add_executable(netpulse
    src/main.cpp
    src/pcap_reader.cpp
    src/live_capture.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/classifier.cpp
    src/reporter.cpp
    src/cli_parser.cpp
)

# We want this executable compiled on Windows too, to discover our interface names!
add_executable(live_capture_test src/live_capture_test.cpp)

# 4. Target Linking and Dependency Management
if(PCAP_LIBRARY)
    message(STATUS "Found Packet Capture Library at: ${PCAP_LIBRARY}")
    
    # Link packet capture library to both targets
    target_link_libraries(netpulse ${PCAP_LIBRARY})
    target_link_libraries(live_capture_test ${PCAP_LIBRARY})
else()
    message(FATAL_ERROR "Could not find libpcap (Linux/Mac) or Npcap/wpcap (Windows). Live capture compilation halted.")
endif()

# Platform-specific linking
if(WIN32)
    target_link_libraries(netpulse ws2_32)
    target_link_libraries(live_capture_test ws2_32)
endif()

# 5. Compiler Warnings Configuration
if(MSVC)
    # Microsoft Visual Studio compiler options
    add_compile_options(/W4)
else()
    # GCC/Clang options
    add_compile_options(-Wall -Wextra)
endif()