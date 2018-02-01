CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT (selfup_ns)

LIST(APPEND CMAKE_MODULE_PATH
	${CMAKE_SOURCE_DIR}/cmake/Modules
)

SET(SELFUP_NS_HEADERS
	include/selfup/NetworkPacket.h
	include/selfup/ns_filesys.h
	include/selfup/ns_gui.h
	include/selfup/ns_helpers.h
	include/selfup/TCPAddress.h
	include/selfup/TCPAsync.h
)
SET(SELFUP_NS_SOURCES
	src/NetworkPacket.cpp
	src/ns_filesys.cpp
	src/ns_gui.cpp
	src/ns_gui_win.cpp
	src/ns_helpers.cpp
	src/ns_selfup_main.cpp
)

SET(SERV_NS_HEADERS
	include/selfup/ns_git_shims.h
	include/selfup/ns_filesys.h
	include/selfup/ns_helpers.h
	include/selfup/NetworkPacket.h
	include/selfup/TCPAddress.h
	include/selfup/TCPAsync.h
)
SET(SERV_NS_SOURCES
	src/NetworkPacket.cpp
	src/ns_filesys.cpp
	src/ns_helpers.cpp
	src/ns_serv_main.cpp
)

SET(ZLIB_INCLUDE_DIR "-NOTFOUND" CACHE PATH "ZLIB include dir")
SET(ZLIB_LIBRARIES "-NOTFOUND" CACHE FILEPATH "ZLIB library")

FIND_PACKAGE(LibGit2 REQUIRED)
FIND_PACKAGE(Shlwapi REQUIRED)

## http://stackoverflow.com/questions/1620918/cmake-and-libpthread/29871891#29871891
## https://cmake.org/cmake/help/v3.6/module/FindThreads.html
##   extra magic for gcc linking with pthreads (-pthread)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)

ADD_EXECUTABLE(selfup_ns ${SELFUP_NS_HEADERS} ${SELFUP_NS_SOURCES})
SET_PROPERTY(TARGET selfup_ns PROPERTY SUFFIX ".exe")
TARGET_COMPILE_DEFINITIONS(selfup_ns PUBLIC _CRT_SECURE_NO_WARNINGS) # grrrr
TARGET_LINK_LIBRARIES(selfup_ns Threads::Threads ${LIBGIT2_LIBRARIES} ${SHLWAPI_LIBRARIES})
TARGET_INCLUDE_DIRECTORIES(selfup_ns PUBLIC ${CMAKE_SOURCE_DIR}/include ${LIBGIT2_INCLUDE_DIR})

ADD_EXECUTABLE(serv_ns ${SERV_NS_HEADERS} ${SERV_NS_SOURCES})
SET_PROPERTY(TARGET serv_ns PROPERTY SUFFIX ".exe")
TARGET_COMPILE_DEFINITIONS(serv_ns PUBLIC _CRT_SECURE_NO_WARNINGS) # grrrr
TARGET_LINK_LIBRARIES(serv_ns Threads::Threads ${ZLIB_LIBRARIES} ${SHLWAPI_LIBRARIES})
TARGET_LINK_LIBRARIES(serv_ns ws2_32) # grrrr
TARGET_INCLUDE_DIRECTORIES(serv_ns PUBLIC ${CMAKE_SOURCE_DIR}/include ${ZLIB_INCLUDE_DIR})
