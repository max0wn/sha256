cmake_minimum_required(VERSION 3.10)

project(sha256
    LANGUAGES C
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(sha256 
    main.c 
    src/sha256.c
)

target_include_directories(sha256 PUBLIC "${PROJECT_SOURCE_DIR}/include")
