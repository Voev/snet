# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Target name
set(TARGET_NAME snet_afpacket)

# Static library target
add_library(${TARGET_NAME} SHARED ${SOURCES})

# Link dependencies
target_link_libraries(
    ${TARGET_NAME}
        PRIVATE
            snet_io
            snet_layers
            casket
)