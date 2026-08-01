cmake_minimum_required(VERSION 3.20)
project(EkosAntivirus C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /WX- /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE)
endif()

include_directories(include)

file(GLOB SOURCES "src/*.c")

add_executable(EkosAntivirus ${SOURCES})

target_link_libraries(EkosAntivirus PRIVATE
    wintrust
    crypt32
    imagehlp
    advapi32
    shell32
)
