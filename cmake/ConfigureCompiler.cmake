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

