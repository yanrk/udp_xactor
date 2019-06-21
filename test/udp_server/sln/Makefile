# arguments
platform = linux/x64



# paths home
project_home           = ..
build_dir              = $(project_home)
bin_dir                = $(project_home)/bin/$(platform)
object_dir             = $(project_home)/.objs
udp_xactor_home        = $(project_home)/../..
cauchy_fec_home        = $(project_home)/../../../cauchy_fec



# includes of udp_xactor headers
udp_xactor_inc_path    = $(udp_xactor_home)/inc
udp_xactor_includes    = -I$(udp_xactor_inc_path)

# includes of cauchy_fec headers
cauchy_fec_inc_path    = $(cauchy_fec_home)/inc
cauchy_fec_includes    = -I$(cauchy_fec_inc_path)

# includes of local headers
local_inc_path         = $(project_home)/inc
local_includes         = -I$(local_inc_path)

# all includes that local solution needs
includes               = $(udp_xactor_includes)
includes              += $(cauchy_fec_includes)
includes              += $(local_includes)



# source files of local solution
local_src_path         = $(project_home)/src
local_source           = $(filter %.cpp, $(shell find $(local_src_path) -depth -name "*.cpp"))



# objects of local solution
local_objects          = $(local_source:$(project_home)%.cpp=$(object_dir)%.o)



# system libraries
system_libs            = -lpthread

# udp_xactor libraries
udp_xactor_lib_inc     = $(udp_xactor_home)/lib/$(platform)
udp_xactor_libs        = -L$(udp_xactor_lib_inc) -ludp_xactor

# cauchy_fec libraries
cauchy_fec_lib_inc     = $(cauchy_fec_home)/lib/$(platform)
cauchy_fec_libs        = -L$(cauchy_fec_lib_inc) -lcauchy_fec

# local depends libraries
depend_libs            = $(udp_xactor_libs)
depend_libs           += $(cauchy_fec_libs)
depend_libs           += $(system_libs)



# output execution
output_exec            = $(bin_dir)/udp_server



# my g++ not support nullptr and 64bits
# so no -m64, and add a macro -Dnullptr=0

# build flags for objects
build_obj_flags        = -std=c++11 -g -Wall -O1 -pipe -fPIC

# build flags for execution
build_exec_flags       = $(build_obj_flags)



# build targets

# let 'build' be default target, build all targets
build    : $(local_objects)
	@echo
	@echo "@@@@@  start making udp_server  @@@@@"
	g++ $(build_exec_flags) -o $(output_exec) $^ $(depend_libs)
	@echo "@@@@@  make udp_server success  @@@@@"
	@echo

cpfile   :
	@cp $(udp_xactor_lib_inc)/* $(bin_dir)/

run      : cpfile
	@export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(bin_dir) && $(output_exec)
# it same as: @env LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$(bin_dir) $(output_exec)

# build all objects
$(object_dir)/%.o:$(project_home)/%.cpp
	@dir=`dirname $@`;      \
    if [ ! -d $$dir ]; then \
        mkdir -p $$dir;     \
    fi
	g++ -c $(build_obj_flags) $(includes) -o $@ $<

clean    :
	rm -rf $(object_dir) $(bin_dir)/*

rebuild  : clean build
