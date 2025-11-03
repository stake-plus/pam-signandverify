cmake_minimum_required(VERSION 3.18)

project(pam_blockchain_module C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(pam_blockchain MODULE
  src/pam_blockchain_module.c
  src/module_config.c
  src/session_client.c
  src/authorized_wallets.c
)

target_include_directories(pam_blockchain
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

find_library(PAM_LIBRARY pam REQUIRED)
find_library(PAM_MISC_LIBRARY pam_misc)

target_link_libraries(pam_blockchain
  PRIVATE
    ${PAM_LIBRARY}
    ${PAM_MISC_LIBRARY}
)

set_target_properties(pam_blockchain PROPERTIES
  OUTPUT_NAME "pam_blockchain"
  PREFIX ""
)

install(TARGETS pam_blockchain
  LIBRARY DESTINATION lib/security
)

install(FILES
  docs/pam_blockchain.conf.example
  DESTINATION etc/security
)

