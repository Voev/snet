# Sources
aux_source_directory(${PROJECT_SOURCE_DIR}/src/tls SOURCES)

# Target
add_library(tls_utils STATIC ${SOURCES})
