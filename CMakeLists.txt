cmake_minimum_required(VERSION 3.22)

project(fridge)

add_executable(fridge
	main.cpp pack.cpp unpack.cpp definitions.hpp
	common/common.cpp common/common.hpp common/minos.cpp common/minos.hpp common/range.hpp)

target_compile_features(fridge PRIVATE cxx_std_17)

target_link_libraries(fridge PRIVATE synchronization)

if (MSVC)
	target_compile_options(fridge PRIVATE /W4 /wd4201)
else()
	target_compile_options(fridge PRIVATE -Wall -Wpedantic -Wextra)
endif()
