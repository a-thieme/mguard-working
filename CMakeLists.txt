# cmake version to be used
cmake_minimum_required(VERSION 3.5)

# project name
project(mguard
        VERSION 0.1
        DESCRIPTION "mGuard")

# flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if (HAVE_TESTS)
    add_compile_definitions(HAVE_TESTS)
endif(HAVE_TESTS)

# dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx)
pkg_check_modules(NAC_ABE REQUIRED libnac-abe)
pkg_check_modules(PSYNC REQUIRED PSync)

# files
file(GLOB_RECURSE NAC_ABE_LIB_SOURCE_FILES "src/*.cpp" "src/**/*.cpp")

# include
include_directories(${NDN_CXX_INCLUDE_DIRS})
include_directories(src)
include_directories(build/src)

add_compile_definitions(SYSCONFDIR="${CMAKE_INSTALL_PREFIX}/etc")
add_compile_definitions(MGUARD_CMAKE_BUILD)

# link
link_directories(${NDN_CXX_LIBRARY_DIRS})

# target
add_executable(mguard sandbox/sandbox.cpp)
#add_library(mguard SHARED ${NAC_ABE_LIB_SOURCE_FILES})
target_compile_options(mguard PUBLIC ${NDN_CXX_CFLAGS} ${NAC_ABE_CFLAGS} ${PSYNC_CFLAGS})
target_link_libraries(mguard PUBLIC ${NDN_CXX_LIBRARIES} ${NAC_ABE_LIBRARIES} ${PSYNC_LIBRARIES})

add_subdirectory(tests)

# install
set(PKG_CONFIG_REQUIRES
        "libndn-cxx >= ${NDN_CXX_VERSION}"
        )
set(PKG_CONFIG_LIBS
        "-L\${libdir} -l${PROJECT_NAME}"
        )
set(PKG_CONFIG_CFLAGS
        "-I\${includedir} -DMGUARD_CMAKE_BUILD"
        )
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/mguard.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc")

include(GNUInstallDirs)
install(TARGETS mguard
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mguard
        )
install(DIRECTORY src/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mguard
        FILES_MATCHING PATTERN "*.h*")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc"
        DESTINATION lib/pkgconfig)

