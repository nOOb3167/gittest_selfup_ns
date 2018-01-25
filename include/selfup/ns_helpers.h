#ifndef _NS_HELPERS_H_
#define _NS_HELPERS_H_

#define GS_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define GS_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define SELFUP_CMD_REQUEST_LATEST_SELFUPDATE_BLOB  1
#define SELFUP_CMD_RESPONSE_LATEST_SELFUPDATE_BLOB 2
#define SELFUP_CMD_REQUEST_BLOB_SELFUPDATE   3
#define SELFUP_CMD_RESPONSE_BLOB_SELFUPDATE  4
#define SELFUP_CMD_REQUEST_LATEST_COMMIT_TREE  5
#define SELFUP_CMD_RESPONSE_LATEST_COMMIT_TREE 6
#define SELFUP_CMD_REQUEST_TREELIST  7
#define SELFUP_CMD_RESPONSE_TREELIST 8
#define SELFUP_CMD_REQUEST_OBJS3        9
#define SELFUP_CMD_RESPONSE_OBJS3      10
#define SELFUP_CMD_RESPONSE_OBJS3_DONE 11

#endif /* _NS_HELPERS_H_ */