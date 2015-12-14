/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __TIZEN_APPFW_MESSAGE_PORT_H__
#define __TIZEN_APPFW_MESSAGE_PORT_H__

#ifdef __GNUC__
#	ifndef EXPORT_API
#		define EXPORT_API __attribute__((visibility("default")))
#	endif
#else
#	define EXPORT_API
#endif

#include <stdbool.h>
#include <bundle.h>
#include <tizen_error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_MESSAGE_PORT_MODULE
 * @{
 */

/**
 * @brief Enumeration for error codes of a message port.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
	MESSAGE_PORT_ERROR_NONE = TIZEN_ERROR_NONE,                                     /**< Successful */
	MESSAGE_PORT_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR,                             /**< Internal I/O error */
	MESSAGE_PORT_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,                   /**< Out of memory */
	MESSAGE_PORT_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,           /**< Invalid parameter */
	MESSAGE_PORT_ERROR_PORT_NOT_FOUND = TIZEN_ERROR_MESSAGE_PORT | 0x01,            /**< The message port of the remote application is not found */
	MESSAGE_PORT_ERROR_CERTIFICATE_NOT_MATCH = TIZEN_ERROR_MESSAGE_PORT | 0x02,     /**< The remote application is not signed with the same certificate */
	MESSAGE_PORT_ERROR_MAX_EXCEEDED = TIZEN_ERROR_MESSAGE_PORT | 0x03,              /**< The size of the message has exceeded the maximum limit */
	MESSAGE_PORT_ERROR_RESOURCE_UNAVAILABLE = TIZEN_ERROR_MESSAGE_PORT | 0x04       /**< Resource is temporarily unavailable */
} message_port_error_e;

/**
 * @brief Called when a message is received.
 * @details The function is called when a message is received from the remote application.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		 @a message is automatically freed by framework when callback returned, you can keep @a message using bundle_dup(). @n
 *				@a remote_port will be set only if the remote application sends a message with its port information using message_port_send_message_with_local_port(), otherwise it is @c NULL. @n
 *				When message is sent from remote application by message_port_send_message_with_local_port() in bidirectional communication, trusted_remote_port is used to check whether remote port is trusted port or not.
 *				This callback is called only in the main thread.
 *
 * @param[in] local_port_id		The local message port ID returned by message_port_register_local_port()
 * @param[in] remote_app_id		The ID of the remote application that sent this message
 * @param[in] remote_port		The name of the remote message port
 * @param[in]	trusted_remote_port		If @c true the remote port is a trusted port, otherwise if @c false it is not
 * @param[in] message			The message passed from the remote application
 * @param[in] user_data			The user data passed from the register function
 * @pre			Either message_port_send_message() or message_port_send_message_with_local_port() from the remote application will invoke this function if you register it using message_port_register_local_port().
 * @see			message_port_register_local_port()
 * @see			message_port_unregister_local_port()
 * @see			message_port_send_message()
 * @see			message_port_send_message_with_local_port()
 */
typedef void (*message_port_message_cb)(int local_port_id, const char *remote_app_id, const char *remote_port, bool trusted_remote_port, bundle *message, void *user_data);

/**
 * @brief Called when a trusted message is received.
 * @details This function is called when a trusted message is received from the remote application.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		 You can keep @a message using  bundle_dup(). @n
 *				@a remote_port will be set only if the remote application sends a message with its port information using message_port_send_trusted_message_with_local_port(), otherwise it is @c NULL. @n
 *				When message is sent from remote application by message_port_send_trusted_message_with_local_port() in bidirectional communication, trusted_remote_port is used to check whether remote port is trusted port or not.
 *				This callback is called only in the main thread.
 * @param[in] trusted_local_port_id		The message port ID returned by message_port_register_trusted_local_port()
 * @param[in] remote_app_id				The ID of the remote application that sent this message
 * @param[in] remote_port				The name of the remote message port
 * @param[in]	trusted_remote_port		If @c true the remote port is a trusted port, otherwise if @c false it is not
 * @param[in] message					The message passed from the remote application
 * @param[in] user_data					The user data passed from the register function
 * @pre			Either message_port_send_trusted_message() or message_port_send_trusted_message_with_local_port() from the remote application will invoke this function if you register it using message_port_register_trusted_local_port().
 * @see			message_port_register_trusted_local_port()
 * @see			message_port_unregister_trusted_local_port()
 * @see			message_port_send_trusted_message()
 * @see			message_port_send_trusted_message_with_local_port()
 */
typedef void (*message_port_trusted_message_cb)(int trusted_local_port_id, const char *remote_app_id, const char *remote_port, bool trusted_remote_port, bundle *message, void *user_data);

/**
 * @brief Registers the local message port.
 * @details If the message port name is already registered, the previous local message port ID returns and the callback function is changed. \n
 *			Multiple message ports can be registered.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		The specified callback is called only in the main thread.
 * @param[in] local_port	The name of the local message port
 * @param[in] callback		The callback function to be called when a message is received
 * @param[in] user_data		The user data to be passed to the callback function
 *
 * @return		A local message port ID on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER	The specified @a local_port or @a callback is NULL
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR			Internal I/O error
 * @see			message_port_unregister_local_port()
 */
EXPORT_API int message_port_register_local_port(const char *local_port, message_port_message_cb callback, void *user_data);

/**
 * @brief		Registers the trusted local message port.
 * @details		If the message port name is already registered, the previous local message port ID returns and the callback function is changed. @n
 *				It allows communications only if the applications are signed with the same certificate which is uniquely assigned to the developer. @n
 *				Multiple message ports can be registered.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		The specified callback is called only in the main thread.
 * @param[in] trusted_local_port	The name of the trusted local message port
 * @param[in] callback		The callback function to be called when a trusted message is received
 * @param[in] user_data		The user data to be passed to the callback function
 * @return		A trusted local message port ID on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER	The specified @a trusted_local_port or @a callback is NULL
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR			Internal I/O error
 * @see			message_port_unregister_trusted_local_port()
 */
EXPORT_API int message_port_register_trusted_local_port(const char *trusted_local_port, message_port_trusted_message_cb callback, void *user_data);

/**
 * @brief Unregisters the local message port.
 * @details This method unregisters the callback function with the specified local port ID.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] local_port_id		The local message port ID
 * @return		0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE				Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER	The specified @a local_port_id is not positive
 * @retval		#MESSAGE_PORT_ERROR_PORT_NOT_FOUND		The specified @a local_port_id cannot be found
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR			Internal I/O error
 * @see			message_port_register_local_port()
 */
EXPORT_API int message_port_unregister_local_port(int local_port_id);

/**
 * @brief		Registers the trusted local message port.
 * @details		This method unregisters the callback function with the specified local port ID. @n
 *				It allows communications only if the applications are signed with the same certificate which is uniquely assigned to the developer.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] trusted_local_port_id		The trusted local message port ID
 * @return		@c 0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE				Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER	The specified @a trusted_local_port_id is not positive
 * @retval		#MESSAGE_PORT_ERROR_PORT_NOT_FOUND		The specified @a trusted_local_port_id cannot be found
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR			Internal I/O error
 * @see			message_port_register_trusted_local_port()
 */
EXPORT_API int message_port_unregister_trusted_local_port(int trusted_local_port_id);

/**
 * @brief Checks whether the message port of a remote application is registered.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		If this function returns a negative error value, the out parameter @a exist will not be changed.
 * @param[in]	remote_app_id		The ID of the remote application
 * @param[in]	remote_port			The name of the remote message port
 * @param[out]	exist				If @c true the message port of the remote application exists,
 *								otherwise @c false
 * @return		@c 0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE				Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER	The specified @a remote_app_id or @a remote_port is NULL
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR Internal	I/O error
 */
EXPORT_API int message_port_check_remote_port(const char *remote_app_id, const char *remote_port, bool *exist);

/**
 * @brief Checks whether the trusted message port of a remote application is registered.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		If this function returns a negative error value, the out parameter @a exist will not be changed.
 * @param[in]	remote_app_id		The ID of the remote application
 * @param[in]	remote_port			The name of the remote message port
 * @param[out]	exist				If @c true  the message port of the remote application exists,
 *								otherwise @c false
 * @return		@c 0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE					Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER		The specified @a remote_app_id or @a remote_port is @c NULL
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY			Out of memory
 * @retval		#MESSAGE_PORT_ERROR_CERTIFICATE_NOT_MATCH	The remote application is not signed with the same certificate
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR				Internal I/O error
 */
EXPORT_API int message_port_check_trusted_remote_port(const char *remote_app_id, const char *remote_port, bool *exist);

/**
 * @brief Sends a message to the message port of a remote application.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks     @a message must be released with bundle_free() after sending the message.
 * @param[in] remote_app_id		The ID of the remote application
 * @param[in] remote_port		The name of the remote message port
 * @param[in] message			The message to be passed to the remote application, the recommended message size is under 4KB
 * @return		0 on success, otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE					Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER		The specified @a remote_app_id, @a remote_port or @a message is NULL
 * @retval		#MESSAGE_PORT_ERROR_PORT_NOT_FOUND			The message port of the remote application cannot be found
 * @retval		#MESSAGE_PORT_ERROR_MAX_EXCEEDED			The size of message has exceeded the maximum limit
 * @retval		#MESSAGE_PORT_ERROR_RESOURCE_UNAVAILABLE	Resource temporarily unavailable
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY			Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR				Internal I/O error
 * @post		It invokes message_port_message_cb() on the remote application.
 * @see			message_port_message_cb()
 * @see			message_port_register_local_port()
 * @see			message_port_unregister_local_port()
 *
 * @code
 * #include <message_port.h>
 *
 * bundle *b = bundle_create();
 * bundle_add(b, "key1", "value1");
 * bundle_add(b, "key2", "value2");
 *
 * int ret = message_port_send_message("0123456789.BasicApp", "BasicAppPort", b);
 *
 * bundle_free(b);
 * @endcode
 */
EXPORT_API int message_port_send_message(const char *remote_app_id, const char *remote_port, bundle *message);

/**
 * @brief Sends a trusted message to the message port of a remote application.
 * @details This method allows communication only if the applications are signed with the same certificate which is uniquely assigned to the developer.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks     You must release @a message using bundle_free() after sending the message.
 * @param[in] remote_app_id		The ID of the remote application
 * @param[in] remote_port		The name of the remote message port
 * @param[in] message			The message to be passed to the remote application, the recommended message size is under 4KB
 * @return		0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE					Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER		The specified @a remote_app_id, @a remote_port or @a message is @c NULL
 * @retval		#MESSAGE_PORT_ERROR_PORT_NOT_FOUND			The message port of the remote application cannot be found
 * @retval		#MESSAGE_PORT_ERROR_CERTIFICATE_NOT_MATCH	The remote application is not signed with the same certificate
 * @retval		#MESSAGE_PORT_ERROR_MAX_EXCEEDED			The size of the message has exceeded the maximum limit
 * @retval		#MESSAGE_PORT_ERROR_RESOURCE_UNAVAILABLE	Resource is temporarily unavailable
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY			Out of memory
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR				Internal I/O error
 * @post		It invokes message_port_trusted_message_cb() on the remote application.
 * @see			message_port_trusted_message_cb()
 * @see			message_port_register_trusted_local_port()
 * @see			message_port_unregister_trusted_local_port()
 */
EXPORT_API int message_port_send_trusted_message(const char *remote_app_id, const char *remote_port, bundle *message);

/**
 * @brief		Sends a message with local port information to the message port of a remote application.
 * @details		This method is used for bidirectional communication.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		You must releas @a message using bundle_free() after sending the message.
 * @param[in]	remote_app_id		The ID of the remote application
 * @param[in]	remote_port			The name of the remote message port
 * @param[in]	message				The message to be passed to the remote application, the recommended message size is under 4KB
 * @param[in]	local_port_id		The message port ID returned by message_port_register_local_port() or message_port_register_trusted_local_port()
 * @return		@c 0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE					Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER		The specified @a remote_app_id, @a remote_port or @a message is @c NULL and
													The specified @a local_port_id is not positive
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY			Out of memory
 * @retval		#MESSAGE_PORT_ERROR_PORT_NOT_FOUND			The port of the local or remote application cannot be found
 * @retval		#MESSAGE_PORT_ERROR_MAX_EXCEEDED			The size of the message has exceeded the maximum limit
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR				Internal I/O error
 * @post		It invokes message_port_message_cb() on the remote application.
 * @see			message_port_message_cb()
 * @see			message_port_register_local_port()
 * @see			message_port_unregister_local_port()
 *
 * @code
 * #include <message_port.h>
 *
 * static void
 * message_port_receive_cb(int local_port_id, const char *remote_app_id, const char *remote_port, bundle *message)
 * {
 * }
 *
 * int main(int argc, char *argv[])
 * {
 *   bundle *b = bundle_create();
 *   bundle_add(b, "key1", "value1");
 *   bundle_add(b, "key2", "value2");
 *
 *   int local_port_id = message_port_register_local_port("HelloPort", message_port_receive_cb);
 *
 *   int ret = message_port_send_message_with_local_port("0123456789.BasicApp", "BasicAppPort", b, local_port_id);
 *
 *   bundle_free(b);
 * }
 * @endcode 
 */
EXPORT_API int message_port_send_message_with_local_port(const char *remote_app_id, const char *remote_port, bundle *message, int local_port_id);

/**
 * @brief		Sends a trusted message with local port information to the message port of a remote application.
 * @details		This method is used for bidirectional communication. @n
 *				It allows communications only if the applications are signed with the same certificate which is uniquely assigned to the developer.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks		You muse release @a message using bundle_free() after sending the message.
 * @param[in]	remote_app_id		The ID of the remote application
 * @param[in]	remote_port			The name of the remote message port
 * @param[in]	message				The message to be passed to the remote application, the recommended message size is under 4KB
 * @param[in]	local_port_id		The message port ID returned by message_port_register_local_port() or message_port_register_trusted_local_port()
 * @return		0 on success,
 *				otherwise a negative error value
 * @retval		#MESSAGE_PORT_ERROR_NONE					Successful
 * @retval		#MESSAGE_PORT_ERROR_INVALID_PARAMETER		The specified @a remote_app_id, @a remote_port or @a message is @c NULL and
													specified @a local_port_id is not positive
 * @retval		#MESSAGE_PORT_ERROR_OUT_OF_MEMORY			Out of memory
 * @retval		#MESSAGE_PORT_ERROR_PORT_NOT_FOUND			The port of the local or remote application cannot be found.
 * @retval		#MESSAGE_PORT_ERROR_CERTIFICATE_NOT_MATCH	The remote application is not signed with the same certificate.
 * @retval		#MESSAGE_PORT_ERROR_MAX_EXCEEDED			The size of the message has exceeded the maximum limit.
 * @retval		#MESSAGE_PORT_ERROR_IO_ERROR				Internal I/O error
 * @post		It invokes message_port_trusted_message_cb() on the remote application.
 * @see			message_port_trusted_message_cb()
 * @see			message_port_register_trusted_local_port()
 * @see			message_port_unregister_trusted_local_port()
 */
EXPORT_API int message_port_send_trusted_message_with_local_port(const char *remote_app_id, const char *remote_port, bundle *message, int local_port_id);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_MESSAGE_PORT_H__ */
