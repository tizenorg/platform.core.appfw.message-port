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


#ifndef __TIZEN_APPFW_MESSAGE_PORT_INTERNAL_H__
#define __TIZEN_APPFW_MESSAGE_PORT_INTERNAL_H__

#include <message_port_error.h>

#ifdef __cplusplus
extern "C" {
#endif

int convert_to_tizen_error(messageport_error_e error);

#ifdef __cplusplus
}
#endif

#endif /*  __TIZEN_APPFW_MESSAGE_PORT_INTERNAL_H__ */
