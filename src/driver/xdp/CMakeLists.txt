# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Target name
set(TARGET_NAME snet_xdp)

# Static library target
add_library(${TARGET_NAME} SHARED ${SOURCES})

# Find required dependencies for AF_XDP support
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBXDP REQUIRED libxdp)

# Link dependencies
target_link_libraries(
    ${TARGET_NAME}
        PRIVATE
            snet_io
            snet_layers
            casket
            ${LIBBPF_LIBRARIES}
            ${LIBXDP_LIBRARIES}
            elf
            z
)

# Include directories from pkg-config (covers both /usr/include and /usr/local/include)
target_include_directories(
    ${TARGET_NAME}
        PRIVATE
            ${LIBBPF_INCLUDE_DIRS}
            ${LIBXDP_INCLUDE_DIRS}
)

# Compiler and linker flags from pkg-config (library paths, etc.)
target_compile_options(
    ${TARGET_NAME}
        PRIVATE
            ${LIBBPF_CFLAGS_OTHER}
            ${LIBXDP_CFLAGS_OTHER}
)

target_link_directories(
    ${TARGET_NAME}
        PRIVATE
            ${LIBBPF_LIBRARY_DIRS}
            ${LIBXDP_LIBRARY_DIRS}
)