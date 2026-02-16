include(FetchContent)

find_package(fpcap QUIET)
if(NOT fpcap_FOUND)
    FetchContent_Declare(
        fpcap
        GIT_REPOSITORY https://github.com/fpcap/fpcap.git
        GIT_TAG        v0.2.0
    )
    FetchContent_MakeAvailable(fpcap)
endif()

# MSVC arch defines (same as examples/)
if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        add_compile_definitions(_AMD64_)
    else()
        add_compile_definitions(_X86_)
    endif()
endif()

add_executable(fdpi_compare compare_output.cpp)
target_link_libraries(fdpi_compare PRIVATE fdpi::fdpi fpcap::fpcap)

target_compile_definitions(fdpi_compare PRIVATE
    FDPI_TRACEFILES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../tracefiles"
)
