cmake_minimum_required(VERSION 3.16)

project(PiDesFire VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(pidesfire
    src/main.cpp
    src/config.cpp
    src/desfire_client.cpp
    src/card_provisioner.cpp
    src/ha_client.cpp
)

target_include_directories(pidesfire PRIVATE src)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBNFC QUIET libnfc)
    pkg_check_modules(LIBFREEFARE QUIET libfreefare)
    pkg_check_modules(LIBCURL QUIET libcurl)
    pkg_check_modules(OPENSSL QUIET openssl)
endif()

if(LIBNFC_FOUND)
    target_compile_definitions(pidesfire PRIVATE PIDESFIRE_HAS_LIBNFC=1)
    target_include_directories(pidesfire PRIVATE ${LIBNFC_INCLUDE_DIRS})
    target_link_directories(pidesfire PRIVATE ${LIBNFC_LIBRARY_DIRS})
    target_link_libraries(pidesfire PRIVATE ${LIBNFC_LIBRARIES})
endif()

if(LIBFREEFARE_FOUND)
    target_compile_definitions(pidesfire PRIVATE PIDESFIRE_HAS_LIBFREEFARE=1)
    target_include_directories(pidesfire PRIVATE ${LIBFREEFARE_INCLUDE_DIRS})
    target_link_directories(pidesfire PRIVATE ${LIBFREEFARE_LIBRARY_DIRS})
    target_link_libraries(pidesfire PRIVATE ${LIBFREEFARE_LIBRARIES})
endif()

if(LIBCURL_FOUND)
    target_compile_definitions(pidesfire PRIVATE PIDESFIRE_HAS_LIBCURL=1)
    target_include_directories(pidesfire PRIVATE ${LIBCURL_INCLUDE_DIRS})
    target_link_directories(pidesfire PRIVATE ${LIBCURL_LIBRARY_DIRS})
    target_link_libraries(pidesfire PRIVATE ${LIBCURL_LIBRARIES})
endif()

if(OPENSSL_FOUND)
    target_compile_definitions(pidesfire PRIVATE PIDESFIRE_HAS_OPENSSL=1)
    target_include_directories(pidesfire PRIVATE ${OPENSSL_INCLUDE_DIRS})
    target_link_directories(pidesfire PRIVATE ${OPENSSL_LIBRARY_DIRS})
    target_link_libraries(pidesfire PRIVATE ${OPENSSL_LIBRARIES})
endif()

install(TARGETS pidesfire RUNTIME DESTINATION bin)

# Copy config files into the build directory so the binary can be run in-place.
foreach(_config config.yaml config.local.yaml)
    if(EXISTS "${CMAKE_SOURCE_DIR}/${_config}")
        configure_file(
            "${CMAKE_SOURCE_DIR}/${_config}"
            "${CMAKE_BINARY_DIR}/${_config}"
            COPYONLY
        )
    endif()
endforeach()