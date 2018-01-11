import capstone
import any_capstone


dis = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

def PROCESSOR_ENTRY():
    return any_capstone.Processor(dis)
