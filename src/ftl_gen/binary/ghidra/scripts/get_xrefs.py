# Ghidra Python script: Get cross-references to or from an address.
#
# Args (via getScriptArgs()):
#   [0] Hex address (e.g. "0x8b420")
#   [1] Direction: "to" (who references this) or "from" (what does this reference)
#
# Output: One JSON line per xref, prefixed with "RESULT:"
#   For "to": {"from_address": "0x8b420", "from_function": "FUN_xxx", "ref_type": "UNCONDITIONAL_CALL"}
#   For "from": {"to_address": "0x8b420", "to_function": "FUN_xxx", "ref_type": "UNCONDITIONAL_CALL"}
#
# @category FTL-Gen
# @author ftl-gen

import json


def get_function_name(addr):
    """Get the name of the function containing an address, or 'unknown'."""
    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionContaining(addr)
    if func:
        return func.getName()
    return "unknown"


def get_xrefs_to(addr_str):
    """Get all references TO a given address."""
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return [{"error": "Invalid address: %s" % addr_str}]

    results = []
    refs = getReferencesTo(addr)
    for ref in refs:
        from_addr = ref.getFromAddress()
        results.append({
            "from_address": "0x%x" % from_addr.getOffset(),
            "from_function": get_function_name(from_addr),
            "ref_type": str(ref.getReferenceType()),
        })

    return results


def get_xrefs_from(addr_str):
    """Get all references FROM the function containing a given address."""
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return [{"error": "Invalid address: %s" % addr_str}]

    func_mgr = currentProgram.getFunctionManager()
    func = func_mgr.getFunctionContaining(addr)
    if func is None:
        return [{"error": "No function at %s" % addr_str}]

    results = []
    body = func.getBody()
    ref_mgr = currentProgram.getReferenceManager()

    # Iterate through all addresses in the function body
    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        cur_addr = addr_iter.next()
        refs = ref_mgr.getReferencesFrom(cur_addr)
        for ref in refs:
            to_addr = ref.getToAddress()
            results.append({
                "to_address": "0x%x" % to_addr.getOffset(),
                "to_function": get_function_name(to_addr),
                "ref_type": str(ref.getReferenceType()),
                "from_instruction": "0x%x" % cur_addr.getOffset(),
            })

    return results


def main():
    args = getScriptArgs()
    if len(args) < 2:
        println("RESULT:" + json.dumps({"error": "Usage: <address> <to|from>"}))
        return

    addr_str = str(args[0]).strip()
    direction = str(args[1]).strip().lower()

    if direction == "to":
        results = get_xrefs_to(addr_str)
    elif direction == "from":
        results = get_xrefs_from(addr_str)
    else:
        results = [{"error": "Direction must be 'to' or 'from', got '%s'" % direction}]

    for result in results:
        println("RESULT:" + json.dumps(result))


main()
