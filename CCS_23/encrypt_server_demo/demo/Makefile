LDFLAGS_O3 = -L$(PWD)/../libhydrogen/build_O3 -lhydrogen -static -fuse-ld=lld -flto
CXXFLAGS_O3 = -std=c++11 -Wall -Wextra -O3 -g

LDFLAGS_O0 = -L$(PWD)/../libhydrogen/build_O0 -lhydrogen -static
CXXFLAGS_O0 = -std=c++11 -Wall -Wextra -g -I$(PWD)/../gnupg/build_static_O0_demo_sections/include

CC=clang
CXX=clang++

BINS = demo_O0 demo_O3
OBJS_O0 = gcry_O0.o
OBJS_O3 = gcry_O3.o

all: $(BINS)

demo_O0: demo.cc
	$(CXX) $(CXXFLAGS_O0) demo.cc -o demo_O0 $(LDFLAGS_O0)

demo_O3: demo.cc
	$(CXX) $(CXXFLAGS_O3) demo.cc -o demo_O3 $(LDFLAGS_O3)

clean:
	rm -f *.o $(BINS)
