cmake_minimum_required(VERSION 3.10)

set(APP_NAME async_client)
aux_source_directory(${PROJECT_SOURCE_DIR}/${APP_NAME} SOURCE_FILES) 
add_executable(${APP_NAME} ${SOURCE_FILES})
target_link_libraries(${APP_NAME} ${OPENSSL_LIBRARIES} "pthread")
target_compile_options(${APP_NAME} PUBLIC "-pthread")
