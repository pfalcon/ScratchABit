IMM_UHEX = None
IMM_SHEX = "shex"
IMM_UDEC = "udec"
IMM_SDEC = "sdec"
IMM_CHAR = "chr"
IMM_ADDR = "addr"


class InvalidAddrException(Exception):
    "Thrown when dereferencing address which doesn't exist in AddressSpace."
    def __init__(self, addr):
        self.args = (addr, hex(addr))
