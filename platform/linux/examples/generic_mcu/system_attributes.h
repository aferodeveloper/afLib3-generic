/**
 * Copyright 2018 Afero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AF_SYSTEM_ATTRIBUTES_H
#define AF_SYSTEM_ATTRIBUTES_H

#define ATTRIBUTE_TYPE_BOOLEAN                                     1
#define ATTRIBUTE_TYPE_SINT8                                       2
#define ATTRIBUTE_TYPE_SINT16                                      3
#define ATTRIBUTE_TYPE_SINT32                                      4
#define ATTRIBUTE_TYPE_SINT64                                      5
#define ATTRIBUTE_TYPE_FIXED_16_16                                 6
#define ATTRIBUTE_TYPE_UTF8S                                      20
#define ATTRIBUTE_TYPE_BYTES                                      21

// The various interfaces we support for the AF_ONLINE_STATUS attribute
#define AF_INTERFACE_BLE                                            1
#define AF_INTERFACE_WIFI                                           2

// Attribute UTC Time
#define AF_UTC_TIME                                               1201
#define AF_UTC_TIME_SZ                                               4
#define AF_UTC_TIME_TYPE                         ATTRIBUTE_TYPE_SINT32

// Attribute Device Id
#define AF_DEVICE_ID                                              1202
#define AF_DEVICE_ID_SZ                                              8
#define AF_DEVICE_ID_TYPE                         ATTRIBUTE_TYPE_BYTES

// Attribute Association Id
#define AF_ASSOCIATION_ID                                         1203
#define AF_ASSOCIATION_ID_SZ                                        12
#define AF_ASSOCIATION_ID_TYPE                    ATTRIBUTE_TYPE_BYTES

// Attribute Company Code
#define AF_COMPANY_CODE                                           1204
#define AF_COMPANY_CODE_SZ                                           1
#define AF_COMPANY_CODE_TYPE                      ATTRIBUTE_TYPE_SINT8

// Attribute Online Status
#define AF_ONLINE_STATUS                                          1205
#define AF_ONLINE_STATUS_SZ                                          3
#define AF_ONLINE_STATUS_TYPE                     ATTRIBUTE_TYPE_SINT8

// Attribute Bootloader Version
#define AF_BOOTLOADER_VERSION                                   2001
#define AF_BOOTLOADER_VERSION_SZ                                   8
#define AF_BOOTLOADER_VERSION_TYPE             ATTRIBUTE_TYPE_SINT64

// Attribute Softdevice Version
#define AF_SOFTDEVICE_VERSION                                   2002
#define AF_SOFTDEVICE_VERSION_SZ                                   8
#define AF_SOFTDEVICE_VERSION_TYPE             ATTRIBUTE_TYPE_SINT64

// Attribute Application Version
#define AF_APPLICATION_VERSION                                  2003
#define AF_APPLICATION_VERSION_SZ                                  8
#define AF_APPLICATION_VERSION_TYPE            ATTRIBUTE_TYPE_SINT64

// Attribute Profile Version
#define AF_PROFILE_VERSION                                      2004
#define AF_PROFILE_VERSION_SZ                                      8
#define AF_PROFILE_VERSION_TYPE                ATTRIBUTE_TYPE_SINT64

// Attribute Command
#define AF_SYSTEM_COMMAND                                      65012
#define AF_SYSTEM_COMMAND_SZ                                       4
#define AF_SYSTEM_COMMAND_TYPE                 ATTRIBUTE_TYPE_SINT32

// Attribute ASR State
#define AF_SYSTEM_ASR_STATE                                    65013
#define AF_SYSTEM_ASR_STATE_SZ                                     1
#define AF_SYSTEM_ASR_STATE_TYPE                ATTRIBUTE_TYPE_SINT8

// Attribute Low Power Warn
#define AF_SYSTEM_LOW_POWER_WARN                               65014
#define AF_SYSTEM_LOW_POWER_WARN_SZ                                1
#define AF_SYSTEM_LOW_POWER_WARN_TYPE           ATTRIBUTE_TYPE_SINT8

// Attribute Linked Timestamp
#define AF_SYSTEM_LINKED_TIMESTAMP                             65015
#define AF_SYSTEM_LINKED_TIMESTAMP_SZ                              4
#define AF_SYSTEM_LINKED_TIMESTAMP_TYPE        ATTRIBUTE_TYPE_SINT32

// Attribute Reboot Reason
#define AF_SYSTEM_REBOOT_REASON                                65019
#define AF_SYSTEM_REBOOT_REASON_SZ                               100
#define AF_SYSTEM_REBOOT_REASON_TYPE            ATTRIBUTE_TYPE_UTF8S

// Attribute MCU Interface
#define AF_SYSTEM_MCU_INTERFACE                                65021
#define AF_SYSTEM_MCU_INTERFACE_SZ                                 1
#define AF_SYSTEM_MCU_INTERFACE_TYPE            ATTRIBUTE_TYPE_SINT8

#endif /* AF_SYSTEM_ATTRIBUTES_H */