# Comment PC9800 interrupts
# @category: PC9800.Python

pc9800ints = {
    0x18: { # Keyboard, CRT BIOS, buzzer
        0x00: "Keyboard: Read key data",
        0x01: "Keyboard: Get key buffer status",
        0x02: "Keyboard: Shift key-Check status",
        0x03: "Keyboard: Initialize keyboard interface",
        0x04: "Keyboard: Key input status check",
        0x05: "Keyboard: Read key code from key buffer",
        0x06: "Keyboard: Buffer initialization",
        0x07: "Keyboard: Shift key status and key data read",
        0x08: "Keyboard: Check shift key status and key data",
        0x09: "Keyboard: Create key data",

        0x0a: "set text video mode",
        0x0b: "get text video mode",
        0x0c: "start text screen display",
        0x0d: "end text screen display",
        0x0e: "set text screen single display area",
        0x0f: "set text screen multiple display area",
        0x10: "set cursor type",
        0x11: "display cursor",
        0x12: "terminate cursor",
        0x13: "set cursor position",
        0x14: "read font pattern 16 dot",
        0x16: "initialize text video RAM",
        0x1A: "define user character",
        0x1b: "set KCG access mode",
        0x1c: "init CRT",
        0x1d: "set display width",
        0x1e: "set cursor type",
        0x1f: "read font patter 24 dot",
        0x20: "define user character 24 dot",
        0x21: "read memory switch",
        0x22: "write memory switch",

        0x19: "init light pen",
        0x15: "get light pen position",

        0x19: "start buzzer",
        0x15: "stop buzzer",
        0x23: "set buzzer frequency",
        0x24: "set buzzer time",

        0x40: "start graphic screen",
        0x41: "stop graphic screen",
        0x42: "set graphic screen mode",
        0x43: "set graphic screen palette register (8 color palette)",
        0x44: "set graphic screen border color",
        0x45: "write bit seqence to VRAM",
        0x46: "read bit seqence from VRAM",
        0x47: "draw line or rectangle",
        0x48: "draw circle",
        0x49: "draw graphic character",
        0x4a: "set graphic screen fast write mode",
    },
    0x1b: { # Floppy disk BIOS
        0x01: "FDD Verify",
        0x02: "FDD Read diagnosis",
        0x03: "FDD Initialization",
        0x04: "FDD Sense",
        0x05: "FDD Data write",
        0x06: "FDD Data read",
        0x07: "FDD Seek to cylinder 0",
        0x09: "FDD Write deleted data",
        0x0A: "FDD Read ID",
        0x0C: "FDD Read deleted data",
        0x0D: "FDD Track format",
        0x0E: "FDD Set Operation mode",
        0x10: "FDD Seek",
    },
    0x1c: { # Timer BIOS
        0x02: "Timer: set interval",
        0x03: "Timer: cancel",
        0x04: "Timer: set timer (one-shot)",
        0x05: "Timer: set timer (repeat)",
        0x06: "Timer: beep function",
    },
    0x21: { # DOS
        0x00: "DOS 1+ - TERMINATE PROGRAM",
        0x0d: "DOS 1+ - DISK RESET",
        0x0f: "DOS 1+ - OPEN FILE USING FCB",
        0x09: "DOS 1+ - WRITE STRING TO STANDARD OUTPUT",
        0x10: "DOS 1+ - CLOSE FILE USING FCB",
        0x14: "DOS 1+ - SEQUENTIAL READ FROM FCB FILE",
        0x1a: "DOS 1+ - SET DISK TRANSFER AREA ADDRESS",
        0x25: "DOS 1+ - SET INTERRUPT VECTOR",
        0x30: "DOS 2+ - GET DOS VERSION",
        0x35: "DOS 2+ - GET INTERRUPT VECTOR",
        0x3c: "DOS 2+ - CREAT - CREATE OR TRUNCATE FILE",
        0x3d: "DOS 2+ - OPEN - OPEN EXISTING FILE",
        0x3e: "DOS 2+ - CLOSE - CLOSE FILE",
        0x3f: "DOS 2+ - READ - READ FROM FILE OR DEVICE",
        0x40: "DOS 2+ - WRITE - WRITE TO FILE OR DEVICE",
        0x43: "DOS 2+ - GET FILE ATTRIBUTES",
        0x48: "DOS 2+ - ALLOCATE MEMORY",
        0x4a: "DOS 2+ - RESIZE MEMORY BLOCK",
        0x4e: "DOS 2+ - FINDFIRST - FIND FIRST MATCHING FILE",
        0x4c: "DOS 2+ - EXIT - TERMINATE WITH RETURN CODE",
    },
    0x40: { # Illegal
    }
}

def addComment(inst, int_n, func):
    codeUnit = listing.getCodeUnitAt(inst.getAddress())
    #if inst.getComment(codeUnit.PLATE_COMMENT) is not None: return
    comment = "INT {:X}h\n".format(int_n)
    if int_n in pc9800ints:
        if func not in pc9800ints[int_n] and int_n == 0x1b: # FDD int hack
            func &= 0xf
        if int_n == 0x40: # FDD int hack
            if func is None: func = 0
            comment += "Illegal interrupt. AH={:X}h".format(func)
        elif func in pc9800ints[int_n]:
            if func is not None:
                comment += "Function {:X}h: ".format(func)
            comment += pc9800ints[int_n][func]
        else: 
            print("Unknown function")
            return
    else:
        print("Unknown interrupt")
        return
    print(comment)
    inst.setComment(codeUnit.PLATE_COMMENT, comment)

listing = currentProgram.getListing()
inst = listing.getInstructions(currentProgram.getMemory(), True)
for i in inst:
    if monitor.isCancelled(): exit()
    if i.getMnemonicString() == "INT":
        int_n = i.getOpObjects(0)[0].getValue()
        commented = False
        prev_i = i
        for _ in range(5): # look back for AH or AX value
            prev_i = prev_i.getPrevious()
            if prev_i == None: break
            if prev_i.getMnemonicString() == "MOV":
                if type(prev_i.getOpObjects(0)[0]) is ghidra.program.model.lang.Register and type(prev_i.getOpObjects(1)[0]) is ghidra.program.model.scalar.Scalar:
                    if prev_i.getOpObjects(0)[0].getName() in ("AH", "AX"):
                        val = prev_i.getOpObjects(1)[0].getValue()
                        if prev_i.getOpObjects(0)[0].getName() == "AX": val >>= 8
                        print("{} INT {:X}h AH {:X}h".format(i.getAddress(), int_n, val))
                        addComment(i, int_n, val)
                        commented = True
                        break
        if not commented: print("{} INT {:X}h Can't find AH".format(i.getAddress(), int_n))

exit()


