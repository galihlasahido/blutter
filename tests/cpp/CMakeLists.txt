cmake_minimum_required(VERSION 3.20)
project(blutter_cpp_tests CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	# <format> is experimental on Clang 15/16; MachOHelper.cpp doesn't use it
	# but the flag is harmless and keeps parity with blutter/CMakeLists.txt.
	add_compile_options(-fexperimental-library)
	add_link_options(-fexperimental-library)
endif()

include(FetchContent)
FetchContent_Declare(
	Catch2
	GIT_REPOSITORY https://github.com/catchorg/Catch2.git
	GIT_TAG        v3.5.3
)
FetchContent_MakeAvailable(Catch2)

# Compile MachOHelper.cpp as part of the test binary. Its first line is
# `#include "pch.h"`, and quote-includes resolve relative to the source file,
# so we can't swap in a shim via the -I path. Instead we predefine the real
# pch.h's include guard (PCH_H) so its body — which drags in the full Dart VM
# toolchain — is skipped when that header is picked up.
add_executable(test_macho_parser
	test_macho_parser.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../../blutter/src/MachOHelper.cpp
)
target_include_directories(test_macho_parser PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/../../blutter/src
)
target_compile_definitions(test_macho_parser PRIVATE PCH_H)
target_link_libraries(test_macho_parser PRIVATE Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(test_macho_parser)
