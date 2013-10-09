/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of message-port.
 *
 * Copyright (C) 2013 Intel Corporation.
 *
 * Contact: Amarnath Valluri <amarnath.valluri@linux.intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef __MESSAGE_PORT_H
#define __MESSAGE_PORT_H

#ifdef __GNUC__
#   ifndef EXPORT_API
#       define EXPORT_API __attribute__((visibility("default")))
#   endif
#else
#   define EXPORT_API
#endif

#include <bundle.h>
#include <glib.h>

#ifndef __cplusplus
typedef gboolean bool;
#endif

G_BEGIN_DECLS

/**
 * messageport_error_e
 * @MESSAGEPORT_ERROR_NONE: No error, operation was successful
 * @MESSAGEPORT_ERROR_IO_ERROR: Internal I/O error
 * @MESSAGEPORT_ERROR_OUT_OF_MEMORY: Out of memory
 * @MESSAGEPORT_ERROR_INVALID_PARAMETER: Invalid paramenter passed
 * @MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND: The message port of the remote application is not found
 * @MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH: The remote application is not signed with the same certificate
 * @MESSAGEPORT_ERROR_MAX_EXCEEDED: The size of message has exceeded the maximum limit
 * 
 * Enumerations of error code, that return by messeage port API.
 * 
 */
typedef enum _messageport_error_e
{
    MESSAGEPORT_ERROR_NONE = 0, 
    MESSAGEPORT_ERROR_IO_ERROR = -1,
    MESSAGEPORT_ERROR_OUT_OF_MEMORY = -2,
    MESSAGEPORT_ERROR_INVALID_PARAMETER = -3,
    MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND = -4,
    MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH = -5,
    MESSAGEPORT_ERROR_MAX_EXCEEDED = -6,
} messageport_error_e;

/**
 * messageport_message_cb:
 * @id: The ID of the local message port to which the message was sent.
 * @remote_app_id: The ID of the remote application which has sent this message, or NULL
 * @remote_port: The name of the remote message port, or NULL
 * @trusted_message: TRUE if the remote message port is trusted port, i.e, it receives message from trusted applications.
 * @message: The message received.
 *
 * This is the function type of the callback used for #messageport_register_local_port or #messageport_register_trusted_local_port.
 * This is called when a message is received from the remote application, #remote_app_id and #remtoe_port will be set
 * if the remote application sends a bidirectional message, otherwise they are NULL.
 *
 */
typedef void (*messageport_message_cb)(int id, const char* remote_app_id, const char* remote_port, bool trusted_message, bundle* message);

/**
 * messageport_register_local_port:
 * @local_port: local_port the name of the local message port
 * @callback: callback The callback function to be called when a message is received at this port
 * 
 * Registers the local message port with name #local_port. If the message port name is already registered,
 * the previous message port id returned, and the callback function is updated with #callback.
 * The #callback function is called when a message is received from a remote application.
 * 
 * Returns: A message port id on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER If either #local_port or #callback is missing or invalid.
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memory error occured
 *          #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
EXPORT_API int
messageport_register_local_port(const char* local_port, messageport_message_cb callback);

/**
 * messageport_register_trusted_local_port:
 * @local_port:  local_port the name of the local message port
 * @callback: callback The callback function to be called when a message is received
 *
 * Registers the trusted local message port with name #local_port. If the message port name is already registered,
 * the previous message port id returned, and the callback function is updated with #callback. 
 * This allows communications only if the applications are signed with the same certificate which is uniquely assigned to the developer.
 *
 * Returns: A message port id on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER If either #local_port or #callback is missing or invalid.
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memory error occured
 *          #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
EXPORT_API int
messageport_register_trusted_local_port(const char* local_port, messageport_message_cb callback);

/**
 * messageport_check_remote_port:
 * @remote_app_id: The ID of the remote application
 * @remote_port: the name of the remote message port to check for.
 * @exist: Return location for status, or NULL.
 *
 * Checks if the message port #remote_port of a remote application #remote_app_id is registered.
 *
 * @param [out] exist @c true if the message port of the remote application exists, otherwise @c false
 * Returns: #MESSAGEPORT_ERROR_NONE if success, otherwise oa negative error value:
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER Either #remote_app_id or #remote_port is missing or invalid
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memory error occured
 *          #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
EXPORT_API messageport_error_e
messageport_check_remote_port(const char* remote_app_id, const char *remote_port, bool *exist);

/**
 * messageport_check_trusted_remote_port:
 * @remote_app_id: The ID of the remote application
 * @remote_port: The name of the remote message port
 *
 * Checks if the trusted message port #remote_port of a remote application #remote_app_id is registered.
 *
 * Returns: #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER Either #remote_app_id or #remote_port is missing or invalid
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memory error occured
 *          #MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH The remote application is not signed with the same certificate
 *          #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
EXPORT_API messageport_error_e
messageport_check_trusted_remote_port(const char* remote_app_id, const char *remote_port, bool *exist);

/**
 * messageport_send_message:
 * @remote_app_id: The ID of the remote application
 * @remote_port: The name of the remote message port
 * @message: Message to be passed to the remote application, the recommended message size is under 4KB
 *
 * Sends a message to the message port of a remote application.
 *
 * Returns #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *         #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter passed
 *         #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memory error occured
 *         #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 *         #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 *         #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 *
 * @code
 * #include <message-port.h>
 *
 * bundle *b = bundle_create();
 * bundle_add(b, "key1", "value1");
 * bundle_add(b, "key2", "value2");
 *
 * int ret = messageport_send_message("0123456789.BasicApp", "BasicAppPort", b);
 *
 * bundle_free(b);
 * @endcode
 */
EXPORT_API messageport_error_e
messageport_send_message(const char* remote_app_id, const char* remote_port, bundle* message);

/**
 * messageport_send_trusted_message:
 * @remote_app_id: The ID of the remote application
 * @remote_port: The name of the remote message port
 * @message: Message to be passed to the remote application, the recommended message size is under 4KB
 *
 * Sends a trusted message to the message port of a remote application. This allows communications only 
 * if the applications are signed with the same certificate which is uniquely assigned to the developer.
 *
 * Returns #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *         #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter passed
 *         #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memeory error occured
 *         #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 *         #MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH The remote application is not signed with the same certificate
 *         #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 *         #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
EXPORT_API messageport_error_e
messageport_send_trusted_message(const char* remote_app_id, const char* remote_port, bundle* message);

/**
 * messageport_send_bidirectional_message:
 * @id: The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @remote_app_id: The ID of the remote application
 * @remote_port: The name of the remote message port
 * @message: Message to be passed to the remote application, the recommended message size is under 4KB

 * Sends a message to the message port #remote_port of a remote application #remote_app_id.
 * This method is used for the bidirectional communication.
 * Remote application can send back the return message to the local message port referred by #id.
 *
 * Returns: #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter passed
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memeory error occured
 *          #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 *          #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 *          #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 *
 * @code
 * #include <message-port.h>
 *
 * static void
 * OnMessageReceived(int id, const char* remote_app_id, const char* remote_port, bool trusted_port, bundle* data)
 * {
 * }
 *
 * int main(int argc, char *argv[])
 * {
 *   bundle *b = bundle_create();
 *   bundle_add(b, "key1", "value1");
 *   bundle_add(b, "key2", "value2");
 *
 *   int id = messageport_register_local_port("HelloPort", OnMessageReceived);
 *
 *   int ret = messageport_send_bidirectional_message(id, "0123456789.BasicApp", "BasicAppPort", b);
 *
 *   bundle_free(b);
 * }
 */
EXPORT_API messageport_error_e
messageport_send_bidirectional_message(int id, const char* remote_app_id, const char* remote_port, bundle* message);

/**
 * messageport_send_bidirectional_trusted_message:
 * @id: The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @remtoe_app_id: The ID of the remote application
 * @remtoe_port: The  name of the remote message port
 * @message: Message to be passed to the remote application, the recommended message size is under 4KB
 *
 * Sends a trusted message to the message port of a remote application. This method is used for the bidirectional communication.
 * Remote application can send back the return message to the local message port referred by #id.
 * This allows communications only if the applications are signed with the same certificate which is uniquely assigned to the developer.
 *
 * Returns: #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter passed
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memeory error occured
 *          #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 *          #MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH The remote application is not signed with the same certificate
 *          #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 *          #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
EXPORT_API messageport_error_e
messageport_send_bidirectional_trusted_message(int id, const char* remote_app_id, const char* remote_port, bundle* message);

/**
 * messageport_get_local_port_name:
 * @id: The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @name: Return location to hold name of the message port or NULL
 *
 * Gets the name of the local message port. On success, the #name is filled with the registered message port name, which muste be released with #free().
 *
 * Returns: #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 *          #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND No local message port found for #id
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 */
EXPORT_API messageport_error_e
messageport_get_local_port_name(int id, char **name);

/**
 * messageport_check_trusted_local_port:
 * @id: The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @is_trusted: Return location to hold the trusted state of the local messge port
 *
 * Checks if the local message port is trusted.
 *
 * Returns: #MESSAGEPORT_ERROR_NONE on success, otherwise a negative error value.
 *          #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter passed
 *          #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND No local message port found for #id
 *          #MESSAGEPORT_ERROR_OUT_OF_MEMORY Memory error occured
 */
EXPORT_API messageport_error_e
messageport_check_trusted_local_port(int id, bool *is_trusted);

G_END_DECLS

#endif /* __MESSAGE_PORT_H */
