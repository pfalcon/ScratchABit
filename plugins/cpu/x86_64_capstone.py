import capstone
import any_capstone


dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
dis.detail = True

def PROCESSOR_ENTRY():
    return any_capstone.Processor(dis)
