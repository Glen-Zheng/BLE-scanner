#
# Copyright (c) 2019 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
# add_subdirectory(C:\Users\zheng\OneDrive\Desktop\Code\firmware\connection_event_trigger\curl-8.7.1_9-win64-mingw.zip);

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(connection_event_trigger)

# NORDIC SDK APP START
target_sources(app PRIVATE
  src/main.c
)
# NORDIC SDK APP END
