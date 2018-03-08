#ifndef _NS_HELPERS_H_
#define _NS_HELPERS_H_

#include <string>

#ifdef _MSC_VER
#  include <malloc.h>
#else
#  include <alloca.h>
#endif

#define GS_ALLOCA_VAR(VARNAME, TT, NELT) TT *VARNAME = (TT *) alloca(sizeof (TT) * (NELT))
#define GS_ALLOCA_ASSIGN(VARNAME, TT, NELT) (VARNAME) = ((TT *) alloca(sizeof (TT) * (NELT)))

#define GS_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define GS_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE  3
#define SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE 4
#define SELFUP_CMD_REQUEST_TREELIST  5
#define SELFUP_CMD_RESPONSE_TREELIST 6
#define SELFUP_CMD_REQUEST_OBJS3       7
#define SELFUP_CMD_RESPONSE_OBJS3      8
#define SELFUP_CMD_RESPONSE_OBJS3_DONE 9
#define SELFUP_CMD_LOGDUMP             10

#define SELFUP_SELFUPDATE_BLOB_ENTRY_FILENAME "selfup_ns.exe"

#if defined (_MSC_VER)
#  define NS_THREAD_LOCAL_DESIGNATOR __declspec( thread )
#else
#  define NS_THREAD_LOCAL_DESIGNATOR __thread
#endif

char decode_hex_char(const char hex_char);
std::string decode_hex(const std::string &hex, bool web_programmer_designed_swapped_hex_mental_illness);
std::string encode_hex(const std::string &bin, bool web_programmer_designed_swapped_hex_mental_illness);

#endif /* _NS_HELPERS_H_ */
