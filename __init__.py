"""
Intezer Analyze — Binary Ninja Plugin

Fetches gene/block-level intelligence from Intezer Analyze and annotates
the current binary view with software-type labels, code-reuse info, and
inline comments.

Setup:
    export INTEZER_API_KEY=<your key>
    # Optional: export INTEZER_BASE_URL=https://your-intezer-instance.com

Usage:
    Tools > Intezer > Fetch Intezer Gene Data
"""

import traceback

import binaryninja as bn
from binaryninja import PluginCommand

from .analysis import BinjaCodeIntelligenceHelper, get_sha256_from_bv
from .api import INTEZER_API_KEY, IntezerAPIException


def _run(bv: bn.BinaryView):
    if not INTEZER_API_KEY:
        bn.log_error('[Intezer] INTEZER_API_KEY environment variable not set.')
        bn.show_message_box(
            'Intezer',
            'INTEZER_API_KEY is not set.\n\nExport it before launching Binary Ninja:\n'
            '  export INTEZER_API_KEY=<your key>',
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon,
        )
        return

    file_path = bv.file.filename
    if not file_path:
        bn.log_error('[Intezer] No file is open.')
        return

    bn.log_info('[Intezer] Computing SHA-256 for {}'.format(file_path))
    try:
        sha256 = get_sha256_from_bv(bv)
    except Exception as ex:
        bn.log_error('[Intezer] Cannot read file: {}'.format(ex))
        return

    bn.log_info('[Intezer] SHA-256: {}'.format(sha256))

    try:
        helper = BinjaCodeIntelligenceHelper(bv)
        block_map, analysis_url = helper.build_block_map(sha256)
    except IntezerAPIException as ex:
        bn.log_error('[Intezer] {}'.format(ex))
        bn.show_message_box(
            'Intezer',
            str(ex),
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.ErrorIcon,
        )
        return
    except Exception:
        bn.log_error('[Intezer] Unexpected error:\n{}'.format(traceback.format_exc()))
        return

    bn.log_info('[Intezer] Loaded {} blocks. Adding comments…'.format(len(block_map)))
    helper.add_comments(block_map)
    helper.export_csv(block_map)

    # Show results panel (UI only available in GUI mode)
    try:
        from .ui import IntezerResultsWidget
        widget = IntezerResultsWidget(bv, block_map, analysis_url, sha256)
        widget.show_panel()
    except ImportError:
        bn.log_info('[Intezer] Running headless — skipping UI panel.')

    bn.log_info('[Intezer] Done. Analysis URL: {}'.format(analysis_url))


PluginCommand.register(
    'Intezer\\Fetch Intezer Gene Data',
    'Fetch block-level gene data from Intezer Analyze and annotate the binary.',
    _run,
)
