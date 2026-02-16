cmake_minimum_required(VERSION 3.20)
project(fdpi VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC AND MSVC_VERSION LESS 1940)
    message(FATAL_ERROR "fdpi requires Visual Studio 2022 17.10+ (MSVC 19.40+) for C++23 support. Detected MSVC version: ${MSVC_VERSION}")
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # in standalone set default settings to ON
    option(FDPI_BUILD_TESTS "Build unit tests (requires GTest)" ON)
    option(FDPI_BUILD_EXAMPLES "Build examples (requires fpcap)" ON)
    option(FDPI_BUILD_BENCHMARKS "Build benchmarks" ON)
    option(FDPI_BUILD_REGRESSION "Build regression tests (requires GTest + fpcap)" ON)
    option(FDPI_BUILD_TOOLS "Build comparison/validation tools (requires fpcap)" ON)
else()
    # if used as library set default settings to OFF
    option(FDPI_BUILD_TESTS "Build unit tests (requires GTest)" OFF)
    option(FDPI_BUILD_EXAMPLES "Build examples (requires fpcap)" OFF)
    option(FDPI_BUILD_BENCHMARKS "Build benchmarks" OFF)
    option(FDPI_BUILD_REGRESSION "Build regression tests (requires GTest + fpcap)" OFF)
    option(FDPI_BUILD_TOOLS "Build comparison/validation tools (requires fpcap)" OFF)
endif()

file(GLOB_RECURSE FDPI_SOURCES CONFIGURE_DEPENDS src/*.cpp)

add_library(fdpi STATIC ${FDPI_SOURCES})
add_library(fdpi::fdpi ALIAS fdpi)

target_include_directories(fdpi
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(fdpi PUBLIC cxx_std_23)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(fdpi PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(FDPI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(FDPI_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(FDPI_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(FDPI_BUILD_REGRESSION)
    enable_testing()
    add_subdirectory(regressions)
endif()

if(FDPI_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# Installation
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS fdpi
    EXPORT fdpiTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/fdpi
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT fdpiTargets
    FILE fdpiTargets.cmake
    NAMESPACE fdpi::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fdpi
)

configure_package_config_file(
    cmake/fdpiConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/fdpiConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fdpi
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/fdpiConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/fdpiConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/fdpiConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fdpi
)
