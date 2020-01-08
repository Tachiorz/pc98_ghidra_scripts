# Comment PC9800 IO
# @category: PC9800.Python

pc9800out = {
    0x00: "Interrupt controller (master) Chip 8259A",
    0x02: "Interrupt controller (master) Chip 8259A",
    0x0a: "Interrupt controller (slave) Chip 8259A",
    0x11: "DMA status",
    0x13: "DMA request",
    0x15: "DMA mask",
    0x17: "DMA mode",
    0x19: "DMA ptr low",
    0x1b: "DMA mask = 0x0F",
    0x1f: "DMA mask",
    0x20: "Programmable Timer Chip upd4990",
    0x21: "DMA (?)",
    0x29: "DMA boundary",
    0x30: "Serial data rs232",
    0x31: "Dipswitch 1",
    0x32: "Serial result rs232",
    0x33: "Dipswitch 0/rs232c/upd4990 state",
    0x35: "System port",
    0x40: "Printer data",
    0x41: "Keyboard data",
    0x42: "Printer status",
    0x43: "Keyboard command/status",
    0x51: "320kb Floppy",
    0x55: "320kb Floppy status",
    0x68: "GDC Mode F/F register 1",
    0x6a: "GDC Mode F/F register 2",
    0x71: "Set Interval timer",
    0x73: "Interval timer/buzzer",
    0x75: "Serial port timeout",
    0x77: "Interval timer channel/status",
    0x7c: "GDC Mode register (counter = 0 on write)",
    0x7e: "CRTC tile write/counter",
    0x7f: "Mouse",
    0x90: "Floppy status",
    0x92: "Floppy data",
    0x94: "Reset floppy controller",
    0xa1: "GDC Character code 2nd byte",
    0xa3: "GDC Character code 1st byte",
    0xa4: "GDC Display screen selection register",
    0xa5: "GDC Character line index",
    0xa6: "GDC Drawing screen selection register",
    0xa8: "GDC Palette register #3, #7",
    0xa9: "CGROM R/W (user char def)",
    0xaa: "GDC Palette register #2, #6",
    0xac: "GDC Palette register #1, #5",
    0xae: "GDC Palette register #0, #4",
}

def addOUTComment(inst, out_n):
    codeUnit = listing.getCodeUnitAt(inst.getAddress())
    #if inst.getComment(codeUnit.PLATE_COMMENT) is not None: return
    comment = "OUT {:X}h\n".format(out_n)
    if out_n in pc9800out:
        comment += pc9800out[out_n]
    else:
        print("Unknown port")
        return
    print(comment)
    inst.setComment(codeUnit.PLATE_COMMENT, comment)

listing = currentProgram.getListing()
inst = listing.getInstructions(currentProgram.getMemory(), True)
for i in inst:
    if monitor.isCancelled(): exit()
    if i.getMnemonicString() == "OUT":
        if type(i.getOpObjects(0)[0]) is ghidra.program.model.scalar.Scalar:
            out_n = i.getOpObjects(0)[0].getValue()
            print("{} OUT {:X}h".format(i.getAddress(), out_n))
            addOUTComment(i, out_n)
        else:
            print("{} OUT {}".format(i.getAddress(), i.getOpObjects(0)[0].getName()))

    if i.getMnemonicString() == "IN":
        if type(i.getOpObjects(0)[0]) is ghidra.program.model.scalar.Scalar:
            out_n = i.getOpObjects(0)[0].getValue()
            print("{} IN {:X}h".format(i.getAddress(), out_n))
            #addINComment(i, out_n)
        else:
            print("{} IN {}".format(i.getAddress(), i.getOpObjects(0)[0].getName()))

exit()


