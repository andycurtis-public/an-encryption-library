# SPDX-FileCopyrightText: 2024-2025 Knode.ai
# SPDX-License-Identifier: Apache-2.0
# Maintainer: Andy Curtis <contactandyc@gmail.com>
cmake_minimum_required(VERSION 3.10)

# Project Configuration
project(an-encryption-library VERSION 0.1.1)

# Variables
set(INCLUDE_DIR_NAME "an-encryption-library")
set(EXTRA_FILES README.md AUTHORS NEWS.md CHANGELOG.md LICENSE NOTICE)
# set(CUSTOM_PACKAGES a-memory-library)
set(THIRD_PARTY_PACKAGES OpenSSL::Crypto)

# Source files
file(GLOB SOURCE_FILES src/*.c)

find_package(a-cmake-library REQUIRED)

include(LibraryConfig)
include(LibraryBuild)

# Testing
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
