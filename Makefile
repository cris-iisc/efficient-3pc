BIN=bin
# compiler settings
CC=g++
GC=gcc

CORE = primitives
LG_DIR = libgarble
LG_OBJ_DIR = libgarble/obj

COMPILER_OPTIONS=

DEBUG_OPTIONS= -g

ARCHITECTURE = $(shell uname -m)

INCLUDE=-I/usr/include

LG_INCLUDES = libgarble/include
LG_OBJECTS = libgarble/obj/*.o
MSGPACK_INC = /opt/include
MSGPACK_LIB = /opt/lib

LIBRARIES = -lpthread  -lssl -lcrypto #-lmsgpack #-L$(MSGPACK_LIB) -lgarble -lgarblec

CFLAGS = -O3 -msse4 -maes -march=x86-64 #-I$(MSGPACK_INC)

CPPFLAGS = -std=c++11 -Drestrict=__restrict__

# all source files and corresponding object files
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp')
# SOURCES_CORE_C := $(shell find ${CORE} -type f -name '*.c')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)
# OBJECTS_CORE_C := $(SOURCES_CORE_C:.c=.o)
LG_SOURCES_CORE := $(shell find ${LG_DIR} -type f -name '*.c')
LG_OBJECTS_CORE := $(LG_SOURCES_CORE:${LG_DIR}/%.c=${LG_OBJ_DIR}/%.o)

# directory for primitives src
SOURCES_PRIM=primitives/*.cpp
# SOURCES_PRIM_C=primitives/*.c
OBJECTS_PRIM=primitives/*.o
# OBJECTS_PRIM_C=primitives/*.co

all: libgarble core exec
	@echo "make all done."

# The test program compiled and create the binary
# ${CC} ${COMPILER_OPTIONS} -o lg_test.exe test/libgarble_test.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
# ${CC} ${COMPILER_OPTIONS} -o 3pc.exe src/3pc.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
exec:
	${CC} ${COMPILER_OPTIONS} -o test.exe test/test.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
	${CC} ${COMPILER_OPTIONS} -o mrz.exe src/mrz_original.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
	${CC} ${COMPILER_OPTIONS} -o 4roundfair.exe src/4roundfair.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
	${CC} ${COMPILER_OPTIONS} -o fair.exe src/mrz_fair.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
	${CC} ${COMPILER_OPTIONS} -o goutput.exe src/mrz_goutput.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}
	${CC} ${COMPILER_OPTIONS} -o 4pc.exe src/4pc_god.cpp  ${OBJECTS_PRIM} ${JG_OBJECTS} ${CFLAGS} ${CPPFLAGS} ${DEBUG_OPTIONS} ${LG_OBJECTS_CORE} ${LIBRARIES} ${INCLUDE}

# this will compile all files amd create the object file
core:${OBJECTS_CORE} #${OBJECTS_CORE_C}

%.o:%.cpp
	${CC} -c $< ${COMPILER_OPTIONS} ${CPPFLAGS} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} -o $@

${LG_OBJECTS_CORE}: ${LG_OBJ_DIR}/%.o:${LG_DIR}/%.c
		${GC} -c $< ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} -o $@

# compiling libgarble
libgarble: ${LG_OBJECTS_CORE}
# only clean example objects, test object and binaries
clean:
	rm -f *.exe ${OBJECTS_PRIM}
cleanall: clean
	rm -f ${LG_OBJECTS_CORE}
