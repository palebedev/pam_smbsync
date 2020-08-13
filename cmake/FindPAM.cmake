find_path(PAM_INCLUDE_DIR NAMES security/_pam_types.h)
find_library(PAM_LIBRARY NAMES pam)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PAM REQUIRED_VARS PAM_INCLUDE_DIR PAM_LIBRARY)

if(PAM_FOUND AND NOT TARGET PAM::PAM)
    add_library(PAM::PAM UNKNOWN IMPORTED)
    target_include_directories(PAM::PAM INTERFACE "${PAM_INCLUDE_DIR}")
    set_target_properties(PAM::PAM PROPERTIES
        IMPORTED_LOCATION "${PAM_LIBRARY}"
        IMPORTED_LINK_INTERFACE_LANGUAGES C
    )
endif()

mark_as_advanced(PAM_INCLUDE_DIR PAM_LIBRARY)

