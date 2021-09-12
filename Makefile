CC := gcc
AR := ar
SRCD := src
TSTD := tests
BLDD := build
BIND := bin
LIBD := lib
INCD := include
DEMOD := demo

EXEC := charla
TEST_EXEC := $(EXEC)_tests

MAIN := $(BLDD)/main.o
LIB := $(LIBD)/$(EXEC).a
LIB_DB := $(LIBD)/$(EXEC)_debug.a

ALL_SRCF := $(wildcard $(SRCD)/*.c)
ALL_TESTF := $(wildcard $(TSTD)/*.c)
ALL_OBJF := $(patsubst $(SRCD)/%, $(BLDD)/%, $(ALL_SRCF:.c=.o))
ALL_FUNCF := $(filter-out $(MAIN), $(ALL_OBJF))
UTIL_OBJF := $(patsubst $(UTILD)/%, $(UTILD)/%, $(ALL_SRCF:.c=.o))

INC := -I $(INCD)

CFLAGS := -Wall -Werror -Wno-unused-function -MMD
DFLAGS := -g -DDEBUG -DCOLOR
PRINT_STAMENTS := -DERROR -DSUCCESS -DWARN -DINFO

STD := -std=gnu11
TEST_LIB := -lcriterion
LIBS := $(LIB) -lpthread -lm
LIBS_DB := $(LIB_DB) -lpthread -lm

CFLAGS += $(STD)

.PHONY: clean all setup debug

all: setup $(EXEC) $(TEST_EXEC)

setup:
	mkdir -p $(BIND) $(BLDD)

debug: CFLAGS += $(DFLAGS) $(PRINT_STAMENTS)
debug: LIBS := $(LIBS_DB)
debug: all

$(EXEC): $(MAIN) $(ALL_FUNCF) $(LIB)
	$(CC) $(MAIN) $(ALL_FUNCF) -o $(BIND)/$(EXEC) $(LIBS)

$(TEST_EXEC): $(ALL_FUNCF) $(LIB)
	$(CC) $(CFLAGS) $(INC) $(ALL_TESTF) $(ALL_FUNCF) -o $(BIND)/$(TEST_EXEC) $(TEST_LIB) $(LIBS)

$(BLDD)/%.o: $(SRCD)/%.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

clean:
	rm -rf $(BLDD) $(BIND)

.PRECIOUS: $(BLDD)/*.d
-include $(BLDD)/*.d
