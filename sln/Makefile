# arguments
runlink                = static
platform               = linux/x64



# paths home
project_home           = ..
build_dir              = $(project_home)/sln
bin_dir                = $(project_home)/lib/$(platform)
object_dir             = $(project_home)/.objs
cauchy_fec_home        = $(project_home)/../cauchy_fec



# includes of cauchy_fec headers
cauchy_fec_inc_path    = $(cauchy_fec_home)/inc
cauchy_fec_includes    = -I$(cauchy_fec_inc_path)

# includes of udp_xactor headers
udp_xactor_inc_path    = $(project_home)/inc
udp_xactor_includes    = -I$(udp_xactor_inc_path)



# all includes that udp_xactor solution needs
includes               = $(cauchy_fec_includes)
includes              += $(udp_xactor_includes)



# source files of udp_xactor solution
udp_xactor_src_path    = $(project_home)/src
udp_xactor_source      = $(filter %.cpp, $(shell find $(udp_xactor_src_path) -depth -name "*.cpp"))



# objects of udp_xactor solution
udp_xactor_objects     = $(udp_xactor_source:$(project_home)%.cpp=$(object_dir)%.o)



# system libraries
system_libs            = -lpthread

# cauchy_fec libraries
cauchy_fec_lib_inc     = $(cauchy_fec_home)/lib/$(platform)
cauchy_fec_libs        = -L$(cauchy_fec_lib_inc) -lcauchy_fec

# udp_xactor depends libraries
udp_xactor_depends     = $(cauchy_fec_libs)
udp_xactor_depends    += $(system_libs)



# output libraries
ifeq ($(runlink), static)
	udp_xactor_outputs = $(bin_dir)/libudp_xactor.a
else ifeq ($(platform), mac)
	udp_xactor_outputs = $(bin_dir)/libudp_xactor.dylib
else
	udp_xactor_outputs = $(bin_dir)/libudp_xactor.so
endif



# build output command line
ifeq ($(runlink), static)
	build_command      = ar -rv $(udp_xactor_outputs) $^
else
	build_command      = g++ -std=c++11 -shared -o $(udp_xactor_outputs) $^ $(udp_xactor_depends)
endif



# build targets
targets                = udp_xactor

# let 'build' be default target, build all targets
build    : $(targets)

udp_xactor   : $(udp_xactor_objects)
	@echo
	@echo "@@@@@  start making udp_xactor  @@@@@"
	$(build_command)
	@echo "@@@@@  make udp_xactor success  @@@@@"
	@echo

# build all objects
$(object_dir)/%.o:$(project_home)/%.cpp
	@dir=`dirname $@`;		\
	if [ ! -d $$dir ]; then	\
		mkdir -p $$dir;		\
	fi
	g++ -c -std=c++11 -g -Wall -O1 -pipe -fPIC $(includes) -o $@ $<

clean    :
	rm -rf $(object_dir) $(bin_dir)/libudp_xactor.*

rebuild  : clean build
