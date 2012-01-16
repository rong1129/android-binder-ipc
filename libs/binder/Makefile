waste := \
    CursorWindow.cpp \
    IMemory.cpp \
    MemoryDealer.cpp \
    MemoryBase.cpp \
    MemoryHeapBase.cpp \
    MemoryHeapPmem.cpp

binder_sources := \
    Binder.cpp \
    BpBinder.cpp \
    IInterface.cpp \
    IPCThreadState.cpp \
    IPermissionController.cpp \
    IServiceManager.cpp \
    Parcel.cpp \
    PermissionCache.cpp \
    ProcessState.cpp \
    Static.cpp

objects += $(patsubst %.cpp,binder/%.o, $(binder_sources))
