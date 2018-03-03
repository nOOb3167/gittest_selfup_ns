# NS_GITCMD : input git command name
# NS_IN : input filename absolute
# NS_OUT : output filename absolute
#
# NS_IN will be run through configure_file
#   GITVER will be available containing
#   the version or an unknown version string

EXECUTE_PROCESS(
	COMMAND "${NS_GITCMD}" rev-parse --short HEAD
	OUTPUT_VARIABLE GITVER
	OUTPUT_STRIP_TRAILING_WHITESPACE
	ERROR_VARIABLE GITERR
)

IF(NOT GITVER)
	SET(GITVER "unknownver")
ENDIF()

CONFIGURE_FILE(${NS_IN} ${NS_OUT})
