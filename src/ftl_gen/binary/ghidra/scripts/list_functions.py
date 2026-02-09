# Ghidra Python script: Search for functions by name pattern.
#
# Compatible with Ghidra 12+ (PyGhidra / CPython).
#
# This is the key tool for finding actual CODE addresses from symbol names.
# Unlike find_strings.py (which finds string data in __cstring), this script
# queries Ghidra's function manager and symbol table for executable function
# entry points.
#
# Args (via getScriptArgs()):
#   [0] Search pattern (substring match, case-insensitive)
#   [1] Optional: max results (default 20)
#
# Output: One JSON line per function, prefixed with "RESULT:"
#   {"name": "BossShip::GetEvent", "address": "0x1002a3f40", "size": 256,
#    "calling_convention": "__thiscall", "is_thunk": false}
#
# @category FTL-Gen
# @author ftl-gen

import json


def list_matching_functions(pattern, max_results=20):
    """Find functions whose name contains the pattern (case-insensitive)."""
    results = []
    pattern_lower = pattern.lower()
    func_mgr = currentProgram.getFunctionManager()

    # Iterate all functions
    func_iter = func_mgr.getFunctions(True)  # forward iterator
    while func_iter.hasNext() and len(results) < max_results:
        func = func_iter.next()
        name = func.getName()

        if pattern_lower in name.lower():
            entry = func.getEntryPoint()
            body = func.getBody()
            sig = func.getSignature()

            results.append({
                "name": name,
                "address": "0x%x" % entry.getOffset(),
                "size": int(body.getNumAddresses()) if body else 0,
                "signature": str(sig) if sig else "",
                "calling_convention": str(func.getCallingConventionName()) if func.getCallingConventionName() else "unknown",
                "is_thunk": func.isThunk(),
                "is_external": func.isExternal(),
                "param_count": func.getParameterCount(),
            })

    return results


def main():
    args = getScriptArgs()
    if not args:
        println("RESULT:" + json.dumps({"error": "No pattern provided. Usage: <pattern> [max_results]"}))
        return

    pattern = str(args[0]).strip()
    max_results = 20
    if len(args) > 1:
        try:
            max_results = int(str(args[1]).strip())
        except ValueError:
            pass

    results = list_matching_functions(pattern, max_results)

    if not results:
        println("RESULT:" + json.dumps({
            "info": "No functions matching '%s'. Try a shorter pattern or check demangled names." % pattern,
            "total_functions": func_count(),
        }))
    else:
        for result in results:
            println("RESULT:" + json.dumps(result))


def func_count():
    """Count total functions in the program."""
    count = 0
    func_iter = currentProgram.getFunctionManager().getFunctions(True)
    while func_iter.hasNext():
        func_iter.next()
        count += 1
    return count


main()
