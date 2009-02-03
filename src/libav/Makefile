CC = gcc
CFLAGS += -Wall -pedantic -fpic

ifdef DEBUG
CFLAGS += -g -O0
endif

VMAR := 0
VMIN := 1
VREL := 0
LIB_NAME := libav
LIB_OBJS := av.o
LIB_DIR := /usr/lib
HDR_NAME := av.h
HDR_DIR := /usr/include

.PHONY: all install uninstall clean

all: $(LIB_NAME).a  $(LIB_NAME).so

$(LIB_NAME).a: $(LIB_OBJS)
	$(AR) $(ARFLAGS) $(LIB_NAME).a $(LIB_OBJS)

$(LIB_NAME).so: $(LIB_OBJS)
	$(CC) -shared -Wl,-soname,$(LIB_NAME).so.$(VMAR) \
		-o $(LIB_NAME).so $(LIB_OBJS)

install: $(LIB_NAME).a $(LIB_NAME).so
	cp $(HDR_NAME) $(HDR_DIR)/$(HDR_NAME)
	cp $(LIB_NAME).a $(LIB_DIR)/$(LIB_NAME).a
	cp $(LIB_NAME).so $(LIB_DIR)/$(LIB_NAME).so.$(VMAR).$(VMIN).$(VREL)
	ln -sf $(LIB_DIR)/$(LIB_NAME).so.$(VMAR).$(VMIN).$(VREL) \
		$(LIB_DIR)/$(LIB_NAME).so.$(VMAR)
	ln -sf $(LIB_DIR)/$(LIB_NAME).so.$(VMAR) \
		$(LIB_DIR)/$(LIB_NAME).so

uninstall:
	$(RM) $(HDR_DIR)/$(HDR_NAME)
	$(RM) $(LIB_DIR)/$(LIB_NAME).a
	$(RM) $(LIB_DIR)/$(LIB_NAME).so
	$(RM) $(LIB_DIR)/$(LIB_NAME).so.$(VMAR)
	$(RM) $(LIB_DIR)/$(LIB_NAME).so.$(VMAR).$(VMIN).$(VREL)

clean:
	$(RM) $(LIB_NAME).a $(LIB_NAME).so $(LIB_OBJS)

