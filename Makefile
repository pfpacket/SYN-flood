CXX         = g++
CXXFLAGS    = -Wall -std=c++0x
LDFLAGS     =
INCLUDES    = -I${BOOST_DIR}/include/
LIBS        = -L${BOOST_DIR}/lib -pedantic -pthread -lboost_system -lboost_program_options
TARGET      = syn-flood
SRC_DIR     = src
OBJS        = ${SRC_DIR}/main.o

all:  $(TARGET)
rebuild:  clean all
	
clean:
	rm -f $(TARGET) $(OBJS)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

.cpp.o: 
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

