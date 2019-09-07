cmake_minimum_required (VERSION 2.6)
project (jabberdclib CXX)

include_directories("${PROJECT_SOURCE_DIR}")

set(SOURCE_FILES base64.cc base64.hh crc32.cc crc32.hh expat.cc expat.hh hash.cc hash.hh hmac.cc hmac.hh jabberid.cc jabberid.hh jid.cc jid.hh jpacket.cc jpacket.hh jutil.cc jutil.hh karma.cc karma.hh lwresc.cc lwresc.hh messages.cc messages.hh namespaces.hh pool.cc pool.hh rate.cc rate.hh socket.cc socket.hh str.cc str.hh xhash.cc xhash.hh xmlnode.cc xmlnode.hh xstream.cc xstream.hh)

add_library(jabberdclib STATIC ${SOURCE_FILES})

install(TARGETS jabberdclib DESTINATION .)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIBMM REQUIRED IMPORTED_TARGET glibmm-2.4)
target_link_libraries(jabberdclib ${GLIBMM_LIBRARIES})
target_include_directories(jabberdclib PUBLIC ${GLIBMM_INCLUDE_DIRS})
target_compile_options(jabberdclib PUBLIC ${GLIBMM_CFLAGS_OTHER})
