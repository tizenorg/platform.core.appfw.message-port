//
// Open Service Platform
// Copyright (c) 2012 Samsung Electronics Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//


#ifndef __APPFW_MESSAGE_PORT_H__
#define __APPFW_MESSAGE_PORT_H__

#include <bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerations of error code for Application.
 */
typedef enum
{
	MESSAGEPORT_ERROR_NONE = 0, /**< Successful */
	MESSAGEPORT_ERROR_IO_ERROR = -1, 		/**< Internal I/O error */
	MESSAGEPORT_ERROR_OUT_OF_MEMORY = -2,		/**< Out of memory */
	MESSAGEPORT_ERROR_INVALID_PARAMETER = -3,	/**< Invalid parameter */
	MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND = -4, 		/**< The message port of the remote application is not found */
	MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH = -5, 	/**< The remote application is not signed with the same certificate */
	MESSAGEPORT_ERROR_MAX_EXCEEDED = -6, 	/**< The size of message has exceeded the maximum limit */
} messageport_error_e;


/**
 * @brief   Called when a message is received from the remote application.
 *
 * @param [in] id The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @param [in] remote_app_id The ID of the remote application which has sent this message
 * @param [in] remote_port The name of the remote message port
 * @param [in] trusted_message @c true if the trusted remote message port is ready to receive the response data
 * @param [in] data the data passed from the remote application
 * @remarks @a data must be released with bundle_free() by you
 * @remark @a remote_app_id and @a remote_port will be set if the remote application sends a bidirectional message, otherwise they are NULL.
 */
typedef void (*messageport_message_cb)(int id, const char* remote_app_id, const char* remote_port, bool trusted_message, bundle* data);


/**
 * @brief Registers the local message port.
 *
 * @param [in] local_port the name of the local message port
 * @param [in] callback The callback function to be called when a message is received
 * @return A message port id on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
int messageport_register_local_port(const char* local_port, messageport_message_cb callback);

/**
 * @brief Registers the trusted local message port.
 *
 * @param [in] local_port the name of the local message port
 * @param [in] callback The callback function to be called when a message is received
 * @return A message port id on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
int messageport_register_trusted_local_port(const char* local_port, messageport_message_cb callback);

/**
 * @brief Checks if the message port of a remote application is registered.
 *
 * @param [in] remote_app_id The ID of the remote application
 * @param [in] remote_port the name of the remote message port
 * @param [out] exist @c true if the message port of the remote application exists, otherwise @c false
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
int messageport_check_remote_port(const char* remote_app_id, const char *remote_port, bool* exist);

/**
 * @brief Checks if the trusted message port of a remote application is registered.
 *
 * @param [in] remote_app_id The ID of the remote application
 * @param [in] remote_port the name of the remote message port
 * @param [out] exist @c true if the message port of the remote application exists, otherwise @c false
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH The remote application is not signed with the same certificate
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
int messageport_check_trusted_remote_port(const char* remote_app_id, const char *remote_port, bool* exist);

/**
 * @brief Sends a message to the message port of a remote application.
 *
 * @param [in] remote_app_id The ID of the remote application
 * @param [in] remote_port the name of the remote message port
 * @param [in] message the message to be passed to the remote application, the recommended message size is under 4KB
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 * @retval #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
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
int messageport_send_message(const char* remote_app_id, const char* remote_port, bundle* message);

/**
 * @brief Sends a trusted message to the message port of a remote application.
 *
 * @param [in] remote_app_id The ID of the remote application
 * @param [in] remote_port the name of the remote message port
 * @param [in] message the message to be passed to the remote application, the recommended message size is under 4KB
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 * @retval #MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH The remote application is not signed with the same certificate
 * @retval #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
int messageport_send_trusted_message(const char* remote_app_id, const char* remote_port, bundle* message);

/**
 * @brief Sends a message to the message port of a remote application. This method is used for the bidirectional communication.
 *
 * @param [in] id The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @param [in] remote_app_id The ID of the remote application
 * @param [in] remote_port the name of the remote message port
 * @param [in] message the message to be passed to the remote application, the recommended message size is under 4KB
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 * @retval #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
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
 *   int ret = messageport_send_message(id, "0123456789.BasicApp", "BasicAppPort", b);
 *
 *   bundle_free(b);
 * }
 */
int messageport_send_bidirectional_message(int id, const char* remote_app_id, const char* remote_port, bundle* data);

/**
 * @brief Sends a trusted message to the message port of a remote application. This method is used for the bidirectional communication.
 *
 * @param [in] id The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @param [in] remote_app_id The ID of the remote application
 * @param [in] remote_port the name of the remote message port
 * @param [in] message the message to be passed to the remote application, the recommended message size is under 4KB
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND The message port of the remote application is not found
 * @retval #MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH The remote application is not signed with the same certificate
 * @retval #MESSAGEPORT_ERROR_MAX_EXCEEDED The size of message has exceeded the maximum limit
 * @retval #MESSAGEPORT_ERROR_IO_ERROR Internal I/O error
 */
int messageport_send_bidirectional_trusted_message(int id, const char* remote_app_id, const char* remote_port, bundle* data);


/**
 * @brief Gets the name of the local message port.
 *
 * @param [in] id The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @param [out] name The name of the local message port
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 * @remarks @a name must be released with free() by you
 */
int messageport_get_local_port_name(int id, char **name);

/**
 * @brief Checks if the local message port is trusted.
 *
 * @param [in] id The message port id returned by messageport_register_local_port() or messageport_register_trusted_local_port()
 * @param [out] @c true if the local message port is trusted
 * @return 0 on success, otherwise a negative error value.
 * @retval #MESSAGEPORT_ERROR_NONE Successful
 * @retval #MESSAGEPORT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #MESSAGEPORT_ERROR_OUT_OF_MEMORY Out of memory
 */
int messageport_check_trusted_local_port(int id, bool *trusted);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __APPFW_MESSAGE_PORT_H__ */