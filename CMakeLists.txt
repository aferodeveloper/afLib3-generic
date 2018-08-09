cmake_minimum_required (VERSION 2.8)

add_library(afLib_c
        af_command.c
        af_command.h
        af_lib.c
        af_lib.h
        af_logger.h
        af_mcu_ota.h
        af_msg_types.h
        af_queue.c
        af_queue.h
        af_status_command.c
        af_status_command.h
        af_transport.h
        af_utils.c
        af_utils.h
        sha2.c
        sha2.h
        hmacsha256.h
        )
