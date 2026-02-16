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
