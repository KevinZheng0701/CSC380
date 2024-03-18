SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
HEADERS := $(wildcard *.h)
TARGETS := kem-enc
TSOURCE := $(wildcard tests/*.c)
TESTS   := $(TSOURCE:.c=)

COMMON   := -O2 -Wall
CFLAGS   := $(CFLAGS) $(COMMON) -I/opt/homebrew/Cellar/gmp/6.3.0/include -I/opt/homebrew/opt/openssl@3/include
CC       := gcc
LDADD    := -L$(shell pkg-config --variable=libdir openssl) -lssl -lcrypto -lgmp -L/opt/homebrew/Cellar/gmp/6.3.0/lib -L/opt/homebrew/opt/openssl@3/lib
LD       := $(CC)
LDFLAGS  := # -L/usr/local/lib/
DEFS     :=
ifeq ($(shell uname),Linux)
DEFS += -DLINUX
endif

IMPL := ske.o rsa.o kem-enc.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

all : $(TARGETS)
.PHONY : all

# {{{ for debugging
debug : CFLAGS += -g -DDEBUG=1
debug : $(TARGETS) $(TESTS)
.PHONY : debug
# }}}

$(OBJECTS) : %.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGETS) : $(IMPL) prf.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

tests : $(TESTS)
.PHONY : tests

$(TESTS) : % : %.o $(filter-out kem-enc.o,$(IMPL)) prf.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY : clean
clean :
	rm -f $(OBJECTS) $(TARGETS) $(TESTS) $(TSOURCE:.c=.o)
