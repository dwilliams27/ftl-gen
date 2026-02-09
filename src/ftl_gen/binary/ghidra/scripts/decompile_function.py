# Ghidra Python script: Decompile the function containing a given address.
#
# Compatible with Ghidra 12+ (PyGhidra / CPython).
#
# Args (via getScriptArgs()):
#   [0] Hex address (e.g. "0x8b420")
#
# Output: One JSON line prefixed with "RESULT:"
#   {"function": "FUN_0008b400", "address": "0x8b400", "size": 256, "pseudocode": "..."}
#
# If no function exists at the address and it's in an executable section,
# this script will attempt to create one before decompiling.
#
# @category FTL-Gen
# @author ftl-gen

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import MemoryAccessException


def is_executable_address(addr):
    """Check if an address is in an executable memory block."""
    memory = currentProgram.getMemory()
    block = memory.getBlock(addr)
    if block is None:
        return False
    return block.isExecute()


def get_section_name(addr):
    """Get the section/block name for an address."""
    memory = currentProgram.getMemory()
    block = memory.getBlock(addr)
    if block is None:
        return "unmapped"
    return block.getName()


def decompile_at(addr_str):
    """Decompile the function containing the given address."""
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return {"error": "Invalid address: %s" % addr_str}

    section = get_section_name(addr)
    executable = is_executable_address(addr)

    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionContaining(addr)

    if func is None:
        if not executable:
            # Address is in a data section — can't decompile
            return {
                "error": "Address %s is in non-executable section '%s' (likely data/RTTI, not code). "
                         "Use list_functions to find actual code addresses by name." % (addr_str, section),
                "function": "none",
                "address": addr_str,
                "section": section,
                "is_executable": False,
                "pseudocode": "",
            }

        # Address is executable but no function defined — try to create one
        try:
            from ghidra.app.cmd.function import CreateFunctionCmd
            cmd = CreateFunctionCmd(addr)
            cmd.applyTo(currentProgram, monitor)
            func = func_mgr.getFunctionContaining(addr)
        except Exception as e:
            pass  # Fall through to getFunctionBefore

    if func is None:
        # Last resort: find nearest function before this address
        func = func_mgr.getFunctionBefore(addr)
        if func is None:
            return {
                "error": "No function found at or near %s (section: %s, executable: %s). "
                         "This address may be in a gap between functions or in a data section." % (
                             addr_str, section, executable),
                "function": "none",
                "address": addr_str,
                "section": section,
                "is_executable": executable,
                "pseudocode": "",
            }
        # Warn that we're using a nearby function, not an exact match
        nearby = True
    else:
        nearby = False

    # Decompile
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    try:
        results = decomp.decompileFunction(func, 60, monitor)

        if results is None or not results.decompileCompleted():
            error_msg = ""
            if results is not None:
                error_msg = str(results.getErrorMessage()) if results.getErrorMessage() else ""
            pseudocode = "// Decompilation failed: %s\n// Function: %s at %s" % (
                error_msg, func.getName(), func.getEntryPoint())
        else:
            decomp_func = results.getDecompiledFunction()
            if decomp_func is not None:
                pseudocode = str(decomp_func.getC())
            else:
                pseudocode = "// Decompiled function object is null\n// Function: %s" % func.getName()
    except Exception as e:
        pseudocode = "// Decompilation error: %s\n// Function: %s" % (str(e), func.getName())
    finally:
        decomp.dispose()

    entry = func.getEntryPoint()
    body = func.getBody()

    result = {
        "function": func.getName(),
        "address": "0x%x" % entry.getOffset(),
        "size": int(body.getNumAddresses()) if body else 0,
        "section": get_section_name(entry),
        "pseudocode": pseudocode,
    }

    if nearby:
        result["warning"] = (
            "Requested address %s is not inside any function. "
            "Decompiled nearest function before it: %s at 0x%x" % (
                addr_str, func.getName(), entry.getOffset()))

    return result


def main():
    try:
        args = getScriptArgs()
        if not args:
            println("RESULT:" + json.dumps({"error": "No address provided"}))
            return

        addr_str = str(args[0]).strip()
        result = decompile_at(addr_str)
        println("RESULT:" + json.dumps(result))
    except Exception as e:
        # Catch-all: always produce output
        println("RESULT:" + json.dumps({
            "error": "Script exception: %s" % str(e),
            "function": "none",
            "address": str(args[0]) if args else "unknown",
            "pseudocode": "",
        }))


main()
