"""
Constants used by the protocol
"""

# messages
MSG_REQUEST      = 1
MSG_REPLY        = 2
MSG_EXCEPTION    = 3

# boxing
LABEL_VALUE      = 1
LABEL_TUPLE      = 2
LABEL_LOCAL_REF  = 3
LABEL_REMOTE_REF = 4

# action handlers
HANDLE_PING        = 1
HANDLE_CLOSE       = 2
HANDLE_GETROOT     = 3
HANDLE_GETATTR     = 4
HANDLE_DELATTR     = 5
HANDLE_SETATTR     = 6
HANDLE_CALL        = 7
HANDLE_CALLATTR    = 8
HANDLE_REPR        = 9
HANDLE_STR         = 10
HANDLE_CMP         = 11
HANDLE_HASH        = 12
HANDLE_DIR         = 13
HANDLE_PICKLE      = 14
HANDLE_DEL         = 15
HANDLE_INSPECT     = 16
HANDLE_BUFFITER    = 17
HANDLE_OLDSLICING  = 18

# optimized exceptions
EXC_STOP_ITERATION = 1

# DEBUG
#for k in globals().keys():
#    globals()[k] = k

