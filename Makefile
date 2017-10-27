CC = arm-linux-g++ -fpermissive
#CC = g++ -fpermissive
SRCS := $(wildcard ./src/*.cpp ./src/socks/*.cpp ./src/utils/*.cpp ./src/thread/*.cpp ./src/th3rd/*.cpp ./src/client/*.cpp)
OBJS := $(patsubst %cpp,%o,$(SRCS))
DEBUG :=
LFLAGS := $(DEBUG)
all : $(OBJS)
	$(CC)  $^ -lpthread $(LFLAGS) -o  xsocks

%.o: %.cpp
	$(CC) -g    -c  $<    -o   $@    -I./src -DLINUX $(DEBUG)

install :
	cp ./bin/xsocks /bin/xsocks

uninstall :
	rm /bin/xsocks

clean :
	-@rm `find ./ -name '*.o'`
