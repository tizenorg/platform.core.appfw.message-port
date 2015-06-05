/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
#include "message_port.h"
#include "message_port_internal.h"

int convert_to_tizen_error(messageport_error_e error)
{
	switch (error) {
		case MESSAGEPORT_ERROR_NONE:
			return MESSAGE_PORT_ERROR_NONE;
		case MESSAGEPORT_ERROR_IO_ERROR:
			return MESSAGE_PORT_ERROR_IO_ERROR;
		case MESSAGEPORT_ERROR_OUT_OF_MEMORY:
			return MESSAGE_PORT_ERROR_OUT_OF_MEMORY;
		case MESSAGEPORT_ERROR_INVALID_PARAMETER:
			return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
		case MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND:
			return MESSAGE_PORT_ERROR_PORT_NOT_FOUND;
		case MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH:
			return MESSAGE_PORT_ERROR_CERTIFICATE_NOT_MATCH;
		case MESSAGEPORT_ERROR_MAX_EXCEEDED:
			return MESSAGE_PORT_ERROR_MAX_EXCEEDED;
		case MESSAGEPORT_ERROR_RESOURCE_UNAVAILABLE:
			return MESSAGE_PORT_ERROR_RESOURCE_UNAVAILABLE;
		default:
			return error;
	}
}
