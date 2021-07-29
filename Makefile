ROOT_PATH=.

# shared toolchain definitions
INC = -I$(ROOT_PATH)/inc
CFLAGS  = -g -Wall -D_GNU_SOURCE $(INC) -lm -lstdc++
LDFLAGS_SHARED = 
LDFLAGS_STATIC = 
LD      = gcc
CC      = gcc
LDXX	= g++
CXX	= g++
AR      = ar

ifeq ($(DEBUG), y)
	CFLAGS += -D__DEBUG__
endif

MLX5_INC = -I$(ROOT_PATH)/rdma-core/build/include
MLX5_LIBS = -L$(ROOT_PATH)/rdma-core/build/lib/statics
MLX5_LIBS += -lmlx5 -libverbs -lnl-3 -lnl-route-3  -lpthread -ldl -lnuma

ifeq ($(CONFIG_MLX5),y)
CFLAGS += -DMLX5
LDFLAGS_SHARED += $(MLX5_LIBS)
LDFLAGS_STATIC += $(MLX5_LIBS)
INC += $(MLX5_INC)
endif

#binary name
APP = mlx5-netperf
# libbase.a - the base library
base_src = $(wildcard base/*.c)
base_obj = $(base_src:.c=.o)

# main - the main binary
SRCS-y := main.c mempool.c mem.c pci.c bitmap.c sysfs.c

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: export build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

build/$(APP)-shared: $(SRCS-y) Makefile | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@


.PHONY: submodules
submodules:
	$(ROOT_PATH)/init_submodules.sh

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true



