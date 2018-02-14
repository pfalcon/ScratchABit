import capstone
import _any_capstone

dis = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 + capstone.CS_MODE_LITTLE_ENDIAN)

def PROCESSOR_ENTRY():
    return _any_capstone.Processor("ppc_32", dis)
