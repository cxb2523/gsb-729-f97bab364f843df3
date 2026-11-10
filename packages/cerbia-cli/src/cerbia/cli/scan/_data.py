import logging
from pathlib import Path

from cerbia.core.models.results import ScanResult

logger = logging.getLogger(__name__)


def write_json_result(result: ScanResult, output_path: Path) -> None:
    """Write the result to a JSON file, creating parent directories if necessary.

    Args:
        result (ScanResult): The scan result to write.
        output_path (Path): The path to the output JSON file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists():
        logger.warning("Overwriting existing output file %s", output_path)

    output_path.write_text(result.model_dump_json(indent=2, ensure_ascii=False))

    logger.debug("JSON results written to %s", output_path)
