from dataclasses import dataclass

PNG_SIGNATURE = bytes([137, 80, 78, 71, 13, 10, 26, 10])
IHDR = "IHDR".encode("ascii")
PLTE = "PLTE".encode("ascii")
IDAT = "IDAT".encode("ascii")
bKGD = "bKGD".encode("ascii")
cHRM = "cHRM".encode("ascii")
gAMA = "gAMA".encode("ascii")
hIST = "hIST".encode("ascii")
pHYs = "pHYs".encode("ascii")
sBIT = "sBIT".encode("ascii")
tEXT = "tEXT".encode("ascii")
tIME = "tIME".encode("ascii")
tRNS = "tRNS".encode("ascii")
zTXt = "zTXt".encode("ascii")
IEND = "IEND".encode("ascii")


@dataclass
class HDR:
    width: int
    height: int
    bit_depth: int
    color_type: int
    comp_method: int
    filt_method: int
    interlace_method: int

def parse_IHDR(data, length):
    if length != 13:
        raise Exception("invalid length IHDR chunk")

    width = int.from_bytes(data[:4])
    height = int.from_bytes(data[4:8])

    if not (0 < width < 2**31 and 0 < height < 2**31):
        raise Exception("invalid width and height in IHDR")

    bit_depth = data[8]
    color_type = data[9]

    if color_type == 0:
        if bit_depth not in [1 << i for i in range(5)]:
            raise Exception("invalid bit depth for color type 0 in IHDR")
    elif color_type in [2, 4, 6]:
        if bit_depth not in [8, 16]:
            raise Exception(f"invalid bit depth for color type {color_type} in IHDR")
    elif color_type == 3:
        if bit_depth not in [1 << i for i in range(4)]:
            raise Exception("invalid bit depth for color type 3 in IHDR")
    else:
        raise Exception("invalid color type in IHDR")

    comp_method = data[10]
    if comp_method != 0:
        raise Exception("invalid compression method given in IHDR")
    filt_method = data[11]
    if filt_method != 0:
        raise Exception("invalid filter method given in IHDR")
    interlace_method = data[12]
    if interlace_method not in [0, 1]:
        raise Exception("invalid interlacing method given in IHDR")

    return HDR(width, height, bit_depth, color_type, comp_method, filt_method,
               interlace_method)

def parse_PLTE(data, length):
    pass

def parse_IDAT(data, length):
    pass

def parse_gAMA(data, length):
    pass

def parse_pHYs(data, length):
    pass

def parse_IEND(data, length):
    pass

# maps every chunk type to its parsing function
parse_chunk = {
    IHDR : parse_IHDR,
    PLTE : parse_PLTE,
    IDAT : parse_IDAT,
    gAMA : parse_gAMA,
    pHYs : parse_pHYs,
    IEND : parse_IEND,
}

def get_chunk_type_properties(chunk_type):
    #check bit 5 (property bit) of each byte

    # byte 1: uppercase = critical, lowercase = ancillary
    if not (chunk_type[0]) & (1 << 5):
        print("critical")
    else:
        print("ancillary")

    # byte 2: uppercase = public, lowercase = private
    if not (chunk_type[1]) & (1 << 5):
        print("public")
    else:
        print("private")

    # byte 3: reserved, must be 0
    if (chunk_type[2]) & (1 << 5):
        raise Exception("Invalid formation of chunk type")

    # byte 4: uppercase = unsafe to copy, lowercase = safe to copy
    if not (chunk_type[3]) & (1 << 5):
        print("unsafe")
    else:
        print("safe")


def chunk_type_critical(chunk_type):
    """Returns True if the chunk_type is critical (i.e. required to be
    recognised by the parser)"""
    return not (chunk_type[0] & (1 << 5))

def open_file(file):
    with open(file, "rb") as f:

        # header
        header = f.read(8)
        if header != PNG_SIGNATURE:
            raise Exception("NOT PNG")

        # chunks
        while True:
            # length
            length = f.read(4)
            if not length:
                break
            length = int.from_bytes(length)
            if length >= 2**31:
                raise Exception("Length of chunk exceeds the limit of (2^31)-1 bytes")

            # type: a 4 letter ASCII string represented as 4 bytes
            chunk_type = f.read(4)
            chunk_data = f.read(length)

            try:
                ans = parse_chunk[chunk_type](chunk_data, length)
                if ans:
                    print(ans)
            except KeyError:
                if chunk_type_critical(chunk_type):
                    raise Exception("Critical chunk not recognised")
                else:
                    print(f"unrecognised chunk type: {chunk_type}")


                

            crc = f.read(4)

            print(f"chunk_type: {chunk_type}")
            print(f"Length: {length}")
            print(f"chunk_data: {chunk_data}")
            print()




if __name__ == "__main__":
    open_file("test.png")
