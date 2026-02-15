include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)

# Prevent overriding the parent project's compiler/linker settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

file(GLOB_RECURSE FDPI_TEST_SOURCES CONFIGURE_DEPENDS *.cpp)

add_executable(fdpi_tests ${FDPI_TEST_SOURCES})

target_link_libraries(fdpi_tests
    PRIVATE
        fdpi::fdpi
        GTest::gtest
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(fdpi_tests)
