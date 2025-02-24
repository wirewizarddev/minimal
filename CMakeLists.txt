cmake_minimum_required(VERSION 3.10)

project(WireWizard)

set(PostgreSQL_INCLUDE_DIRS "/usr/include/postgresql")

find_package(PostgreSQL REQUIRED)
find_package(CURL REQUIRED)

option(CMAKE_BUILD_TYPE "Choose build type: minimal or classic" "classic")

if(CMAKE_BUILD_TYPE STREQUAL "classic")
  if(PostgreSQL_FOUND AND CURL_FOUND)
    include_directories(${PostgreSQL_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})

    add_executable(ww src/cli.c src/database.c src/wireguard.c src/request.c)

    target_compile_options(ww PRIVATE -Wall -pedantic -std=gnu17)
    
    if(DEFINED TEMPDIR AND TEMPDIR)
      target_compile_definitions(ww PUBLIC TEMPDIR=1)
    endif()
    if(DEFINED BASHENABLE AND BASHENABLE)
      target_compile_definitions(ww PUBLIC BASHENABLE=1)
    endif()

    target_link_libraries(ww ${PostgreSQL_LIBRARIES} ${CURL_LIBRARIES})
  else()
    message(FATAL_ERROR "PostgreSQL or CURL library not found")
  endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "minimal")
  if(CURL_FOUND)
    include_directories(${CURL_INCLUDE_DIRS})
    
    add_executable(ww src/cli.c src/wireguard.c src/request.c)

    target_compile_options(ww PRIVATE -Wall -pedantic -std=gnu17)
    
    if(DEFINED TEMPDIR AND TEMPDIR)
      target_compile_definitions(ww PUBLIC TEMPDIR=1)
    endif()
    if(DEFINED BASHENABLE AND BASHENABLE)
      target_compile_definitions(ww PUBLIC BASHENABLE=1)
    endif()

    target_link_libraries(ww ${CURL_LIBRARIES})
  else()
    message(FATAL_ERROR "CURL library not found")
  endif()
endif()
