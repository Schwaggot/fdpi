find_package(fpcap QUIET)

if(NOT fpcap_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        fpcap
        GIT_REPOSITORY https://github.com/fpcap/fpcap.git
        GIT_TAG        v0.2.0
    )
    FetchContent_MakeAvailable(fpcap)
endif()

# fpcap's public headers include <winsock2.h>/<windows.h> which need the architecture
# define, but fpcap only sets it via directory-scoped add_definitions().
if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        add_compile_definitions(_AMD64_)
    else()
        add_compile_definitions(_X86_)
    endif()
endif()

add_executable(basic_decode basic_decode.cpp)
target_link_libraries(basic_decode PRIVATE fdpi::fdpi fpcap::fpcap)

add_executable(flow_tracker flow_tracker.cpp)
target_link_libraries(flow_tracker PRIVATE fdpi::fdpi fpcap::fpcap)

add_executable(dns_monitor dns_monitor.cpp)
target_link_libraries(dns_monitor PRIVATE fdpi::fdpi fpcap::fpcap)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP IMPORTED_TARGET libpcap)
endif()
if(NOT PCAP_FOUND)
    find_library(PCAP_LIBRARY pcap)
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
        set(PCAP_FOUND TRUE)
    endif()
endif()

if(PCAP_FOUND)
    add_executable(libpcap_decode libpcap_decode.cpp)
    if(TARGET PkgConfig::PCAP)
        target_link_libraries(libpcap_decode PRIVATE fdpi::fdpi PkgConfig::PCAP)
    else()
        target_link_libraries(libpcap_decode PRIVATE fdpi::fdpi ${PCAP_LIBRARY})
        target_include_directories(libpcap_decode PRIVATE ${PCAP_INCLUDE_DIR})
    endif()
endif()
