# Target name
set(TARGET_NAME snet_tcp_app)

# Sources
file(GLOB_RECURSE SOURCES *.cpp)

# Static library target
add_executable(${TARGET_NAME} ${SOURCES})

# Dependencies
target_link_libraries(${TARGET_NAME}
    PUBLIC
        snet_layers
        casket
)
