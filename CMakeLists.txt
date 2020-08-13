cmake_minimum_required(VERSION 3.11)

project(pam_smbsync
    DESCRIPTION "PAM module to sync passwords with Samba"
    VERSION 1.0.0
    LANGUAGES C
)

add_library(${PROJECT_NAME} MODULE src/pam_smbsync.c)

target_compile_features(${PROJECT_NAME} PUBLIC c_std_99)
set_target_properties(${PROJECT_NAME} PROPERTIES
    C_EXTENSIONS OFF
    PREFIX ""
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(PAM REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE PAM::PAM)

include(GNUInstallDirs)

set(PAM_MODULE_DIR "${CMAKE_INSTALL_LIBDIR}/security" CACHE PATH
    "PAM module directory")

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION "${PAM_MODULE_DIR}")

