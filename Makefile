CC       := gcc
CFLAGS   := -O2 -g -Wall
INCLUDES := -I.

COMMON_SRC := common.c
COMMON_OBJ := common.o

.PHONY: all clean

all: $(COMMON_OBJ)

$(COMMON_OBJ): $(COMMON_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(COMMON_OBJ)