import csv
import hashlib
import os

import binaryninja as bn
from binaryninja import HighlightStandardColor

import tenacity

from .api import INTEZER_API_KEY, IntezerAPIException, Proxy

# Optional block coloring by software type (set to True to enable)
IS_COLOR_BLOCKS = False

# BN highlight colors mapped to software types
HIGHLIGHT_COLORS = {
    'malware': HighlightStandardColor.RedHighlightColor,
    'application': HighlightStandardColor.GreenHighlightColor,
    'common': HighlightStandardColor.YellowHighlightColor,
    'administration_tool': HighlightStandardColor.BlueHighlightColor,
    'unknown': HighlightStandardColor.WhiteHighlightColor,
}

SOFTWARE_TYPE_DISPLAY = {
    'administration_tool': 'Administration Tool',
    'application': 'Application',
    'installer': 'Installer',
    'library': 'Library',
    'packer': 'Packer',
    'malware': 'Malware',
    'interpreter': 'Non Native',
    'malicious_packer': 'Malicious Packer',
    'common': 'Common',
    'unknown': 'Unknown',
}


def format_software_type(software_type):
    return SOFTWARE_TYPE_DISPLAY.get(software_type, software_type)


def format_code_reuse(code_reuse):
    return ', '.join(code_reuse) if code_reuse else ''


def get_sha256_from_bv(bv: 'bn.BinaryView') -> str:
    """Hash the raw binary bytes (not the .bndb wrapper)."""
    raw = bv.parent_view if bv.parent_view else bv
    data = raw.read(raw.start, raw.length)
    return hashlib.sha256(data).hexdigest()


def get_sha256(file_path):
    with open(file_path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class BinjaCodeIntelligenceHelper:
    def __init__(self, bv: bn.BinaryView):
        self._bv = bv
        self._proxy = Proxy(INTEZER_API_KEY)

    @property
    def imagebase(self):
        return self._bv.start

    def _get_absolute_address(self, block_address):
        return block_address + self.imagebase

    def _get_function_for_address(self, addr):
        funcs = self._bv.get_functions_containing(addr)
        return funcs[0] if funcs else None

    def _get_basic_block_for_address(self, addr):
        func = self._get_function_for_address(addr)
        if not func:
            return None
        for block in func.basic_blocks:
            if block.start <= addr < block.end:
                return block
        return None

    def _get_strings_in_block(self, block_start, block_end):
        strings = []
        for s in self._bv.get_strings(block_start, block_end - block_start):
            strings.append('"{}"'.format(s.value))
        return strings

    def _get_block_map_from_api(self, sha256):
        file_path = self._bv.file.filename
        result_url = self._proxy.create_plugin_report(sha256, file_path)
        bn.log_info('[Intezer] Fetching results from {}'.format(result_url))
        try:
            ida_plugin_report = self._proxy.poll_result(result_url)
        except tenacity.RetryError:
            raise IntezerAPIException(
                'Intezer analysis timed out waiting for results. '
                'The job may still be running — try again in a few minutes.'
            )

        analysis_url = self._proxy.get_analysis_url(result_url)
        bn.log_info('[Intezer] Analysis URL: {}'.format(analysis_url))

        if not ida_plugin_report.get('blocks'):
            raise ValueError('No genes were extracted from the file.')

        block_map = {}
        for block_address_str, record in ida_plugin_report['blocks'].items():
            abs_addr = self._get_absolute_address(int(block_address_str))
            block_map[abs_addr] = {'block_address': abs_addr}
            block_map[abs_addr].update(record)

        return block_map, analysis_url

    def _enrich_block_map(self, block_map):
        for abs_addr, entry in block_map.items():
            func = self._get_function_for_address(abs_addr)
            bb = self._get_basic_block_for_address(abs_addr)

            entry['function_name'] = func.name if func else ''
            entry['function_address'] = func.start if func else 0
            entry['end_block_address'] = bb.end if bb else abs_addr
            entry['strings'] = self._get_strings_in_block(
                abs_addr, entry['end_block_address']
            )

            if IS_COLOR_BLOCKS and bb:
                stype = entry.get('software_type', 'unknown')
                color = HIGHLIGHT_COLORS.get(stype, HighlightStandardColor.WhiteHighlightColor)
                bb.set_user_highlight(color)

        return block_map

    def build_block_map(self, sha256):
        block_map, analysis_url = self._get_block_map_from_api(sha256)
        return self._enrich_block_map(block_map), analysis_url

    def add_comments(self, block_map):
        for entry in block_map.values():
            addr = entry['block_address']
            stype = format_software_type(entry.get('software_type', 'unknown'))
            reuse = format_code_reuse(entry.get('code_reuse', []))
            body = '{} - {}'.format(stype, reuse)
            comment = '------ INTEZER ------\n{}\n---------------------'.format(body)

            existing = self._bv.get_comment_at(addr)
            if existing:
                comment = '{}\n{}'.format(existing, comment)
            self._bv.set_comment_at(addr, comment)

            end_addr = entry.get('end_block_address')
            if end_addr and end_addr != addr:
                self._bv.set_comment_at(end_addr, '------ End of INTEZER block ------')

    def export_csv(self, block_map):
        try:
            file_path = self._bv.file.filename
            sha256 = get_sha256(file_path)[:8]
            out_path = os.path.join(
                os.path.dirname(file_path),
                'intezer_blocks_{}.csv'.format(sha256),
            )
            fields = [
                'Function Address',
                'Function Name',
                'Block Address',
                'End Block Address',
                'Software Type',
                'Code Reuse',
                'Strings',
            ]
            with open(out_path, 'w', newline='') as fh:
                writer = csv.writer(fh)
                writer.writerow(fields)
                for entry in block_map.values():
                    writer.writerow([
                        hex(entry.get('function_address', 0)),
                        entry.get('function_name', ''),
                        hex(entry['block_address']),
                        hex(entry.get('end_block_address', 0)),
                        format_software_type(entry.get('software_type', '')),
                        format_code_reuse(entry.get('code_reuse', [])),
                        ', '.join(entry.get('strings', [])),
                    ])
            bn.log_info('[Intezer] CSV saved to {}'.format(out_path))
        except Exception as ex:
            bn.log_error('[Intezer] Failed to write CSV: {}'.format(ex))
