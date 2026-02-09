# Ghidra Python script: Read raw bytes from the binary at a given address.
#
# Compatible with Ghidra 12+ (PyGhidra / CPython).
# Uses jpype Java arrays instead of Jython's jarray.
#
# Args (via getScriptArgs()):
#   [0] Hex address (e.g. "0x8b420")
#   [1] Number of bytes to read (e.g. "32")
#
# Output: One JSON line prefixed with "RESULT:"
#   {"address": "0x8b420", "length": 32, "hex": "554889e54883ec20..."}
#
# @category FTL-Gen
# @author ftl-gen

import json

import jpype


def get_bytes_at(addr_str, length):
    """Read raw bytes from the binary at the given address."""
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return {"error": "Invalid address: %s" % addr_str}

    memory = currentProgram.getMemory()

    try:
        # Create Java byte array via jpype
        java_bytes = jpype.JArray(jpype.JByte)(length)
        bytes_read = memory.getBytes(addr, java_bytes)

        # Convert signed Java bytes to hex string
        hex_str = ""
        for i in range(bytes_read):
            b = int(java_bytes[i])
            if b < 0:
                b = b + 256  # Convert signed to unsigned
            hex_str += "%02x" % b

        return {
            "address": addr_str,
            "length": bytes_read,
            "hex": hex_str,
        }
    except Exception as e:
        return {
            "error": "Failed to read bytes at %s: %s" % (addr_str, str(e)),
            "address": addr_str,
            "length": 0,
            "hex": "",
        }


def main():
    args = getScriptArgs()
    if len(args) < 2:
        println("RESULT:" + json.dumps({"error": "Usage: <address> <length>"}))
        return

    addr_str = str(args[0]).strip()
    try:
        length = int(str(args[1]).strip())
    except ValueError:
        println("RESULT:" + json.dumps({"error": "Invalid length: %s" % args[1]}))
        return

    # Cap at 4096 bytes for safety
    length = min(length, 4096)

    result = get_bytes_at(addr_str, length)
    println("RESULT:" + json.dumps(result))


main()
