# Comment PC9800 IO
# @category: PC9800.Python

pc9800out = {
    0x00: "Interrupt controller (master) Chip 8259A",
    0x02: "Interrupt controller (master) Chip 8259A",
    0x0a: "Interrupt controller (slave) Chip 8259A",
    0x43: "Keyboard interface",
    0x68: "GDC Mode F/F register 1",
    0x6a: "GDC Mode F/F register 2",
    0xa1: "GDC Character code 2nd byte",
    0xa3: "GDC Character code 1st byte",
    0xa4: "GDC Display screen selection register",
    0xa5: "GDC Line counter",
    0xa6: "GDC Drawing screen selection register",
    0xa8: "GDC Palette register #3, #7",
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


