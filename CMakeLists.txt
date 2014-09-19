#################################################
##
## Create Custom Tokutek Audit Library.
##
add_library(audit-enterprise SHARED audit.cpp)
add_dependencies(audit-enterprise generate_error_codes generate_action_types)
