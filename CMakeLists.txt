cmake_minimum_required(VERSION 3.25)

project(imws)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#add_compile_options(-pthread -Wall)
add_compile_options(-O2)
add_compile_options(-g -ggdb)
#add_compile_options(-fsanitize=address)

file(GLOB SOURCES "src/*.cpp" "src/bxr/*.cpp")
add_executable(imws ${SOURCES})

#set(Boost_USE_STATIC_LIBS OFF)
#set(Boost_USE_DEBUG_RUNTIME OFF)

find_package(libOTe REQUIRED
        PATHS libOTe
        NO_DEFAULT_PATH
        NO_CMAKE_ENVIRONMENT_PATH
        NO_CMAKE_PATH
        NO_SYSTEM_ENVIRONMENT_PATH
        NO_CMAKE_SYSTEM_PATH
        NO_CMAKE_FIND_ROOT_PATH)
target_link_libraries(imws oc::libOTe)

find_package(IPCL 2.0.0
        HINTS /opt/intel/ipcl
        REQUIRED)
target_link_libraries(imws IPCL::ipcl)

find_package(IPPCP
        HINTS pailliercryptolib/build/ext_ipp-crypto/ippcrypto_install/opt/intel/ipcl/
        REQUIRED)
target_link_libraries(imws IPPCP::ippcp)
