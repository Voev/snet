# C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

get_cmake_property(PROJECT_LANGUAGES ENABLED_LANGUAGES)

if ("C" IN_LIST PROJECT_LANGUAGES)
    include(CheckCCompilerFlag)

    function(add_c_compiler_flag flag)
        string(FIND "${CMAKE_C_FLAGS}" "${flag}" flag_already_set)
        set(flag_name "${flag}_supported")
        string(REPLACE "-" "" flag_supported "${flag_name}")

        if(flag_already_set EQUAL -1)
            check_c_compiler_flag("${flag}" C_${flag_supported})

            if(C_${flag_supported})
                add_compile_options($<$<COMPILE_LANGUAGE:C>:${flag}>)
            else()
                message(FATAL_ERROR "Unsupported C compiler flag: ${flag}")
            endif()

            unset(C_${flag_supported} CACHE)
        endif()
    endfunction()
endif()

if ("CXX" IN_LIST PROJECT_LANGUAGES)
    include(CheckCXXCompilerFlag)

    function(add_cxx_compiler_flag flag)
        string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
        set(flag_name "${flag}_supported")
        string(REPLACE "-" "" flag_supported "${flag_name}")

        if(flag_already_set EQUAL -1)
            check_cxx_compiler_flag("${flag}" CXX_${flag_supported})

            if(CXX_${flag_supported})
                add_compile_options($<$<COMPILE_LANGUAGE:CXX>:${flag}>)
            else()
                message(FATAL_ERROR "Unsupported CXX compiler flag: ${flag}")
            endif()

            unset(CXX_${flag_supported} CACHE)
        endif()
    endfunction()
endif()

function(add_compiler_flag flag)
    if ("C" IN_LIST PROJECT_LANGUAGES)
        add_c_compiler_flag(${flag})
    endif()
    if ("CXX" IN_LIST PROJECT_LANGUAGES)
        add_cxx_compiler_flag(${flag})
    endif()
endfunction()

# Compiler warning options
option(ENABLE_PEDANTIC "Enable pedantic compile mode" ON)
option(ENABLE_STRICT "Enable strict compile mode" ON)
option(ENABLE_WERROR "Enable treating warning as error" ON)

# Debug options
option(ENABLE_ADDRESS_SANITIZER "enable address sanitizer support" OFF)
option(ENABLE_UB_SANITIZER "enable undefined behavior sanitizer support" OFF)
option(ENABLE_THREAD_SANITIZER "enable thread sanitizer support" OFF)

if(ENABLE_PEDANTIC)
    add_compiler_flag(-Wpedantic)
endif(ENABLE_PEDANTIC)

if (ENABLE_STRICT)
    add_compiler_flag(-Wall)
    add_compiler_flag(-Wextra)
endif (ENABLE_STRICT)

if (ENABLE_WERROR)
    add_compiler_flag(-Werror) 
endif (ENABLE_WERROR)

add_compiler_flag(-DOPENSSL_SUPPRESS_DEPRECATED)

if (CMAKE_GENERATOR STREQUAL "Unix Makefiles")
  set(CMAKE_COLOR_MAKEFILE ON)
endif()

# Enables build with -fcolor-diagnostics if available
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  set(CMAKE_COLOR_DIAGNOSTICS ON)
endif()

if (ENABLE_ADDRESS_SANITIZER)
    set(ASAN_CXX_FLAGS -fsanitize=address)
    set(ASAN_LINKER_FLAGS -fsanitize=address)
    set(CMAKE_REQUIRED_FLAGS "${ASAN_LINKER_FLAGS}")
    check_cxx_compiler_flag("${ASAN_CXX_FLAGS}" HAVE_ADDRESS_SANITIZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if (HAVE_ADDRESS_SANITIZER)
        add_compile_options(${ASAN_CXX_FLAGS})
        add_link_options(${ASAN_LINKER_FLAGS})
    else ()
        message(SEND_ERROR "Could not enable the address sanitizer!")
    endif ()
endif (ENABLE_ADDRESS_SANITIZER)

if (ENABLE_UB_SANITIZER)
    set(UBSAN_CXX_FLAGS -fsanitize=undefined -fno-sanitize=alignment)
    set(UBSAN_LINKER_FLAGS -fsanitize=undefined -fno-sanitize=alignment)
    set(CMAKE_REQUIRED_FLAGS "${UBSAN_LINKER_FLAGS}")
    check_cxx_compiler_flag("${UBSAN_CXX_FLAGS}" HAVE_UB_SANITIZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if (HAVE_UB_SANITIZER)
        add_compile_options(${UBSAN_CXX_FLAGS})
        add_link_options(${UBSAN_LINKER_FLAGS})
    else ()
        message(SEND_ERROR "Could not enable the undefined behavior sanitizer!")
    endif ()
endif (ENABLE_UB_SANITIZER)

if (ENABLE_THREAD_SANITIZER)
    set(TSAN_CXX_FLAGS -fsanitize=thread)
    set(TSAN_LINKER_FLAGS -fsanitize=thread)
    set(CMAKE_REQUIRED_FLAGS "${TSAN_LINKER_FLAGS}")
    check_cxx_compiler_flag("${TSAN_CXX_FLAGS}" HAVE_THREAD_SANITIZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if (HAVE_THREAD_SANITIZER)
        add_compile_options(${TSAN_CXX_FLAGS})
        add_link_options(${TSAN_LINKER_FLAGS})
    else ()
        message(SEND_ERROR "Could not enable the thread sanitizer!")
    endif ()
endif (ENABLE_THREAD_SANITIZER)
