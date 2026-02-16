include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

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

add_executable(fdpi_regression main.cpp formatter.cpp regression_test.cpp)
target_link_libraries(fdpi_regression PRIVATE fdpi::fdpi fpcap::fpcap GTest::gtest)

target_compile_definitions(fdpi_regression PRIVATE
    FDPI_TRACEFILES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../tracefiles"
    FDPI_BASELINES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/baselines"
)

include(GoogleTest)
gtest_discover_tests(fdpi_regression)
