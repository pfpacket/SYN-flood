CC	 = g++
CFLAGS	 = -Wall -g -std=c++0x
LDFLAGS	 =
INCLUDES = -I${BOOST_DIR}/include/
LIBS	 = -L${BOOST_DIR}/lib -lboost_system -pedantic -pthread -lboost_thread
TARGET	 = syn-flood
OBJS	 = main.o

all:	$(TARGET)

test:	$(TARGET)
	./$(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	-rm -f $(TARGET) $(OBJS) .nfs* *~ \#* core

.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<
