#################################################
##
## Create Custom Tokutek Audit Library.
##
add_library(audit_enterprise SHARED audit.cpp)
add_dependencies(audit_enterprise install_tdb_h generate_error_codes generate_action_types)
install(TARGETS audit_enterprise DESTINATION ${INSTALL_LIBDIR} COMPONENT tokumx_audit_libs_shared)

if (TOKUMX_ENTERPRISE_CREATE_EXPORTS)
  file(RELATIVE_PATH _relative_source_dir "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
  install(TARGETS audit_enterprise DESTINATION "${_relative_source_dir}" COMPONENT tokumx_enterprise_exports EXPORT tokumx_enterprise_exports)
  exports_install(audit_enterprise "\${INSTALL_LIBDIR}" tokumx_audit_libs_shared)
  unset(_relative_source_dir)
endif ()
