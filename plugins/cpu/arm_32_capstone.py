import capstone
import any_capstone


arch_id = "arm_32"

dis_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
dis_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

def PROCESSOR_ENTRY():
    return any_capstone.Processor(dis_arm, dis_thumb)
