def chunk_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    """Split text into overlapping chunks for similarity comparison.

    Args:
        text (str): Source text to chunk.
        chunk_size (int): Character length per chunk.
        overlap (int): Character overlap between consecutive chunks.

    Returns:
        list[str]: Overlapping text chunks.
    """
    if overlap >= chunk_size:
        raise ValueError(f"overlap ({overlap}) must be less than chunk_size ({chunk_size})")

    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    step = chunk_size - overlap

    for i in range(0, len(text) - overlap, step):
        chunks.append(text[i : i + chunk_size])

    return chunks
