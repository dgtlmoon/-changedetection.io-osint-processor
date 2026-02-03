"""
Pluggy plugin implementation for OSINT Reconnaissance Processor.

This module implements the changedetectionio plugin interface to register
the OSINT processor with the main application.
"""

from changedetectionio.pluggy_interface import hookimpl
from loguru import logger


@hookimpl
def register_processor():
    """Register the OSINT reconnaissance processor.

    Returns:
        dict: Processor registration information
    """
    try:
        # Import the processor module
        from . import processor
        from . import name, description, processor_weight, list_badge_text

        return {
            'processor_name': 'osint_recon',
            'processor_module': processor,
            'processor_class': processor.perform_site_check,
            'metadata': {
                'name': name,
                'description': description,
                'processor_weight': processor_weight,
                'list_badge_text': list_badge_text,
            }
        }
    except Exception as e:
        logger.error(f"Failed to register OSINT processor: {e}")
        return None
