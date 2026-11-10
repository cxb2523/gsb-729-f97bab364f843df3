def pattern_covers(existing: str, candidate: str) -> bool:
    if existing == candidate:
        return True

    if "*" not in existing:
        return False

    literals = [part for part in existing.split("*") if part]
    if not literals:
        return True

    if not existing.startswith("*") and not candidate.startswith(literals[0]):
        return False

    if not existing.endswith("*") and not candidate.endswith(literals[-1]):
        return False

    search_start = 0
    for literal in literals:
        index = candidate.find(literal, search_start)
        if index == -1:
            return False

        search_start = index + len(literal)

    return True
