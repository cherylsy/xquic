# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.14

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/xumengxin/Desktop/xmx/xquic

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/tls_server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/tls_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tls_server.dir/flags.make

CMakeFiles/tls_server.dir/tests/tls_server.c.o: CMakeFiles/tls_server.dir/flags.make
CMakeFiles/tls_server.dir/tests/tls_server.c.o: ../tests/tls_server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/tls_server.dir/tests/tls_server.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tls_server.dir/tests/tls_server.c.o   -c /Users/xumengxin/Desktop/xmx/xquic/tests/tls_server.c

CMakeFiles/tls_server.dir/tests/tls_server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tls_server.dir/tests/tls_server.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/xumengxin/Desktop/xmx/xquic/tests/tls_server.c > CMakeFiles/tls_server.dir/tests/tls_server.c.i

CMakeFiles/tls_server.dir/tests/tls_server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tls_server.dir/tests/tls_server.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/xumengxin/Desktop/xmx/xquic/tests/tls_server.c -o CMakeFiles/tls_server.dir/tests/tls_server.c.s

# Object files for target tls_server
tls_server_OBJECTS = \
"CMakeFiles/tls_server.dir/tests/tls_server.c.o"

# External object files for target tls_server
tls_server_EXTERNAL_OBJECTS =

tls_server: CMakeFiles/tls_server.dir/tests/tls_server.c.o
tls_server: CMakeFiles/tls_server.dir/build.make
tls_server: ../libs/openssl/libssl.so.3
tls_server: ../libs/openssl/libcrypto.so.3
tls_server: libxquic.a
tls_server: CMakeFiles/tls_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable tls_server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tls_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tls_server.dir/build: tls_server

.PHONY : CMakeFiles/tls_server.dir/build

CMakeFiles/tls_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tls_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tls_server.dir/clean

CMakeFiles/tls_server.dir/depend:
	cd /Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/xumengxin/Desktop/xmx/xquic /Users/xumengxin/Desktop/xmx/xquic /Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug /Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug /Users/xumengxin/Desktop/xmx/xquic/cmake-build-debug/CMakeFiles/tls_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/tls_server.dir/depend

