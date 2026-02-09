# Ghidra Python script: Find strings matching patterns and their cross-references.
#
# Compatible with Ghidra 12+ (PyGhidra / CPython).
#
# Args (via getScriptArgs()):
#   [0] Comma-separated list of string patterns to search for
#
# Output: One JSON line per found string, prefixed with "RESULT:"
#   {"value": "SCRAP_COLLECTOR", "address": "0x1a3f40", "xrefs": ["0x8b420", "0xc1a30"]}
#
# @category FTL-Gen
# @author ftl-gen

import json


def find_matching_strings(patterns):
    """Find defined strings that match any of the given patterns."""
    results = []
    pattern_set = set(patterns)

    listing = currentProgram.getListing()

    # Iterate over all defined data looking for string types
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        dt = data.getDataType()
        if dt is None:
            continue

        dt_name = dt.getName()
        # Check for string-like data types
        if "string" not in dt_name.lower() and "CString" not in dt_name:
            continue

        value = data.getValue()
        if value is None:
            continue

        value = str(value)

        # Check for exact match or whole-word substring match
        matched = False
        if value in pattern_set:
            matched = True
        else:
            for pattern in patterns:
                # Only match if pattern is a substantial substring (>3 chars)
                if len(pattern) > 3 and pattern in value:
                    matched = True
                    break

        if matched:
            address = data.getAddress()
            xrefs = get_xrefs_to_address(address)
            results.append({
                "value": value,
                "address": "0x%x" % address.getOffset(),
                "xrefs": xrefs,
            })

    return results


def get_xrefs_to_address(address):
    """Get all code cross-references to a given address."""
    xref_list = []
    refs = getReferencesTo(address)
    for ref in refs:
        from_addr = ref.getFromAddress()
        xref_list.append("0x%x" % from_addr.getOffset())
    return xref_list


def main():
    args = getScriptArgs()
    if not args:
        println("RESULT:" + json.dumps({"error": "No patterns provided"}))
        return

    # Parse comma-separated patterns
    raw_patterns = str(args[0])
    patterns = [p.strip() for p in raw_patterns.split(",") if p.strip()]

    results = find_matching_strings(patterns)

    for result in results:
        println("RESULT:" + json.dumps(result))


main()
