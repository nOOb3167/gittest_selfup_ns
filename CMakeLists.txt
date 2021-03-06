CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT (selfup_ns)

OPTION(NS_OPTION_EX_CONFIG_EXTRA OFF)
OPTION(NS_OPTION_ARCHIVE "archive" OFF)
SET(NS_ARCHIVE_FILE "${CMAKE_BINARY_DIR}/selfup_ns.zip" CACHE FILEPATH "archive path")

LIST(APPEND CMAKE_MODULE_PATH
	${CMAKE_SOURCE_DIR}/cmake/Modules
)

FIND_PACKAGE(Git REQUIRED)

ADD_CUSTOM_TARGET(GenVersion
	COMMAND "${CMAKE_COMMAND}"
		-D "NS_GITCMD=${GIT_EXECUTABLE}"
		-D "NS_IN=${CMAKE_SOURCE_DIR}/include/selfup/ns_version.h.in"
		-D "NS_OUT=${CMAKE_BINARY_DIR}/ns_version.h"
		-P "${CMAKE_SOURCE_DIR}/cmake/Modules/GenVersion.cmake"
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	COMMENT "Generating Version (From Git)"
)

FUNCTION(NS_GENERATE_HEADER VARNAME INFILE OUTFILE)
	ADD_CUSTOM_COMMAND(
		OUTPUT "${OUTFILE}"
		DEPENDS "${INFILE}"
		COMMAND "${CMAKE_COMMAND}"
			-D "NS_VARNAME=${VARNAME}"
			-D "NS_IN=${INFILE}"
			-D "NS_OUT=${OUTFILE}"
			-P "${CMAKE_SOURCE_DIR}/cmake/Modules/GenHeader.cmake"
		COMMENT "Generating Header (Hex) (${INFILE} -> ${OUTFILE})"
	)
ENDFUNCTION()

NS_GENERATE_HEADER(imgpbblip_96_32_   ${CMAKE_SOURCE_DIR}/data/imgpbblip_96_32_.data   ${CMAKE_BINARY_DIR}/imgpbblip_96_32_.h)
NS_GENERATE_HEADER(imgpbempty_384_32_ ${CMAKE_SOURCE_DIR}/data/imgpbempty_384_32_.data ${CMAKE_BINARY_DIR}/imgpbempty_384_32_.h)
NS_GENERATE_HEADER(imgpbfull_384_32_  ${CMAKE_SOURCE_DIR}/data/imgpbfull_384_32_.data  ${CMAKE_BINARY_DIR}/imgpbfull_384_32_.h)
NS_GENERATE_HEADER(imglogo_100_100_   ${CMAKE_SOURCE_DIR}/data/imglogo_100_100_.data  ${CMAKE_BINARY_DIR}/imglogo_100_100_.h)
NS_GENERATE_HEADER(g_conf_builtin_str ${CMAKE_SOURCE_DIR}/data/ns_conf_builtin.conf       ${CMAKE_BINARY_DIR}/ns_conf_builtin.h)

SET(COMMON_NS_HEADERS
	include/selfup/NetworkPacket.h
	include/selfup/ns_conf.h
	include/selfup/ns_crash.h
	include/selfup/ns_filesys.h
	include/selfup/ns_git_shims.h
	include/selfup/ns_helpers.h
	include/selfup/ns_log.h
	include/selfup/ns_systemd.h
	include/selfup/ns_thread.h
	include/selfup/TCPAddress.h
	include/selfup/TCPSocket.h
)

SET(COMMON_NS_SOURCES
	src/NetworkPacket.cpp
	src/ns_conf.cpp
	src/ns_crash.cpp
	src/ns_filesys.cpp
	src/ns_git_shims.cpp
	src/ns_helpers.cpp
	src/ns_log.cpp
	src/ns_thread.cpp
	src/TCPAddress.cpp
	src/TCPSocket.cpp
)

SET(SELFUP_NS_HEADERS
	${COMMON_NS_HEADERS}
	include/selfup/ns_git_aux.h
	include/selfup/ns_gui.h
	include/selfup/ns_selfup_aux.h
	${CMAKE_BINARY_DIR}/imgpbblip_96_32_.h
	${CMAKE_BINARY_DIR}/imgpbempty_384_32_.h
	${CMAKE_BINARY_DIR}/imgpbfull_384_32_.h
	${CMAKE_BINARY_DIR}/imglogo_100_100_.h
	${CMAKE_BINARY_DIR}/ns_conf_builtin.h
)
SET(SELFUP_NS_SOURCES
	${COMMON_NS_SOURCES}
	src/ns_git_aux.cpp
	src/ns_gui.cpp
	src/ns_gui_win.cpp
	src/ns_selfup_aux.cpp
	src/ns_systemd.cpp
	src/ns_selfup_main.cpp
)

SET(SERV_NS_HEADERS
	${COMMON_NS_HEADERS}
	include/selfup/TCPAsync.h
	${CMAKE_BINARY_DIR}/ns_conf_builtin.h
)
SET(SERV_NS_SOURCES
	${COMMON_NS_SOURCES}
	src/ns_serv_main.cpp
	src/ns_systemd.cpp
	src/TCPAsync.cpp
)

SET(EX_NS_HEADERS
	include/selfup/NetworkPacket.h
	include/selfup/ns_filesys.h
	include/selfup/ns_git_aux.h
	include/selfup/ns_git_shims.h
	include/selfup/ns_helpers.h
	include/selfup/ns_ex.h
	include/selfup/ns_ex_config.h
	include/selfup/TCPAddress.h
	include/selfup/TCPSocket.h
)
SET(EX_NS_SOURCES
	src/NetworkPacket.cpp
	src/ns_filesys.cpp
	src/ns_git_aux.cpp
	src/ns_git_shims.cpp
	src/ns_helpers.cpp
	src/ns_ex.cpp
	src/ns_ex_config.cpp
	src/ns_ex_main.cpp
	src/TCPAddress.cpp
	src/TCPSocket.cpp
)

SET(ZLIB_INCLUDE_DIR "-NOTFOUND" CACHE PATH "ZLIB include dir")
SET(ZLIB_LIBRARIES "-NOTFOUND" CACHE FILEPATH "ZLIB library")

IF(WIN32)
FIND_PACKAGE(LibGit2 REQUIRED)
FIND_PACKAGE(Shlwapi REQUIRED)
ENDIF()

## http://stackoverflow.com/questions/1620918/cmake-and-libpthread/29871891#29871891
## https://cmake.org/cmake/help/v3.6/module/FindThreads.html
##   extra magic for gcc linking with pthreads (-pthread)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)

IF(WIN32)
ADD_EXECUTABLE(selfup_ns ${SELFUP_NS_HEADERS} ${SELFUP_NS_SOURCES})
ADD_DEPENDENCIES(selfup_ns GenVersion)
SET_PROPERTY(TARGET selfup_ns PROPERTY SUFFIX ".exe")
TARGET_COMPILE_DEFINITIONS(selfup_ns PUBLIC NS_DEF_USING_LIBGIT2)
TARGET_COMPILE_DEFINITIONS(selfup_ns PUBLIC _CRT_SECURE_NO_WARNINGS) # grrrr
TARGET_COMPILE_OPTIONS(selfup_ns PUBLIC /wd4101) # grrrr
TARGET_LINK_LIBRARIES(selfup_ns Threads::Threads ${LIBGIT2_LIBRARIES} ${ZLIB_LIBRARIES} ${SHLWAPI_LIBRARIES})
TARGET_LINK_LIBRARIES(selfup_ns msimg32) # grrrr
TARGET_INCLUDE_DIRECTORIES(selfup_ns PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/include ${LIBGIT2_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})
ENDIF()

IF(WIN32)
ADD_EXECUTABLE(ex_ns ${EX_NS_HEADERS} ${EX_NS_SOURCES})
SET_PROPERTY(TARGET ex_ns PROPERTY SUFFIX ".exe")
TARGET_COMPILE_DEFINITIONS(ex_ns PUBLIC NS_DEF_USING_LIBGIT2)
TARGET_COMPILE_DEFINITIONS(ex_ns PUBLIC _CRT_SECURE_NO_WARNINGS) # grrrr
IF(NS_OPTION_EX_CONFIG_EXTRA)
COMPILE_DEFINITIONS(ex_ns PUBLIC NS_EX_CONFIG_EXTRA_HAVE)
ENDIF()
TARGET_COMPILE_OPTIONS(ex_ns PUBLIC /wd4101) # grrrr
TARGET_LINK_LIBRARIES(ex_ns Threads::Threads ${LIBGIT2_LIBRARIES} ${ZLIB_LIBRARIES} ${SHLWAPI_LIBRARIES})
TARGET_INCLUDE_DIRECTORIES(ex_ns PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/include ${LIBGIT2_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})
ENDIF()

ADD_EXECUTABLE(serv_ns ${SERV_NS_HEADERS} ${SERV_NS_SOURCES})
ADD_DEPENDENCIES(serv_ns GenVersion)
SET_PROPERTY(TARGET serv_ns PROPERTY SUFFIX ".exe")
IF(WIN32)
TARGET_COMPILE_DEFINITIONS(serv_ns PUBLIC _CRT_SECURE_NO_WARNINGS) # grrrr
TARGET_COMPILE_OPTIONS(serv_ns PUBLIC /wd4101) # grrrr
ENDIF()
TARGET_LINK_LIBRARIES(serv_ns Threads::Threads ${ZLIB_LIBRARIES} ${SHLWAPI_LIBRARIES})
IF(WIN32)
TARGET_LINK_LIBRARIES(serv_ns ws2_32) # grrrr
ENDIF()
TARGET_INCLUDE_DIRECTORIES(serv_ns PUBLIC ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/include ${ZLIB_INCLUDE_DIR})

IF(NS_OPTION_ARCHIVE)
	ADD_CUSTOM_COMMAND(TARGET selfup_ns
		POST_BUILD
		BYPRODUCTS "${NS_ARCHIVE_FILE}"
		COMMAND "${CMAKE_COMMAND}"
			-E copy "$<TARGET_FILE:selfup_ns>" "${CMAKE_BINARY_DIR}/selfup_ns.exe"
		COMMAND "${CMAKE_COMMAND}"
			-E tar cf "${NS_ARCHIVE_FILE}" --format=zip -- "${CMAKE_BINARY_DIR}/selfup_ns.exe"
		COMMENT "Generating Archive (${NS_ARCHIVE_FILE})"
	)
ENDIF()

IF(NS_OPTION_ARCHIVE)
	INSTALL(FILES
		"${NS_ARCHIVE_FILE}"
		DESTINATION "data"
	)
ENDIF()

IF(WIN32)
  set(NS_MAYBE_SELFUP_NS selfup_ns ex_ns)
  set(NS_MAYBE_PDB $<TARGET_PDB_FILE:selfup_ns> $<TARGET_PDB_FILE:ex_ns> $<TARGET_PDB_FILE:serv_ns>)
ENDIF()

INSTALL(TARGETS serv_ns ${NS_MAYBE_SELFUP_NS}
	LIBRARY DESTINATION "lib"
	RUNTIME DESTINATION "bin"
	ARCHIVE DESTINATION "lib"
)

INSTALL(FILES
	${NS_MAYBE_PDB}
	data/upload.sh
	DESTINATION "bin"
)
