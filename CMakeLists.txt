CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT (selfup_ns)

LIST(APPEND CMAKE_MODULE_PATH
	${CMAKE_SOURCE_DIR}/cmake/Modules
)

SET(SELFUP_NS_HEADERS
	include/selfup/NetworkPacket.h
	include/selfup/ns_filesys.h
	include/selfup/TCPSocket.h
)
SET(SELFUP_NS_SOURCES
	src/NetworkPacket.cpp
	src/ns_filesys.cpp
	src/ns_selfup_main.cpp
)

FIND_PACKAGE(LibGit2 REQUIRED)

## http://stackoverflow.com/questions/1620918/cmake-and-libpthread/29871891#29871891
## https://cmake.org/cmake/help/v3.6/module/FindThreads.html
##   extra magic for gcc linking with pthreads (-pthread)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)

ADD_EXECUTABLE(selfup_ns ${SELFUP_NS_HEADERS} ${SELFUP_NS_SOURCES})
SET_PROPERTY(TARGET selfup_ns PROPERTY SUFFIX ".exe")
TARGET_LINK_LIBRARIES(selfup_ns Threads::Threads ${LIBGIT2_LIBRARIES})
TARGET_INCLUDE_DIRECTORIES(selfup_ns PUBLIC ${CMAKE_SOURCE_DIR}/include ${LIBGIT2_INCLUDE_DIR})
