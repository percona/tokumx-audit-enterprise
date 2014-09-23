#################################################
##
## Create Custom Tokutek Audit Library.
##
add_library(audit_enterprise SHARED audit.cpp)
add_dependencies(audit_enterprise generate_error_codes generate_action_types)
install(TARGETS audit_enterprise DESTINATION ${INSTALL_LIBDIR} COMPONENT tokubackup_libs_shared)
