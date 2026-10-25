"""Real Root TCP mark helpers for fixtures that supply their own VPP buffers."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def mark_fixture():
    # Keep the production offset/width assertions and all classifier logic.
    # The fixture already declares its controlled vlib_buffer_t dependency.
    return (ROOT/'src/product/vpp/product_root_dns_tcp_mark.h').read_text().replace(
        '#include <vlib/vlib.h>','/* vlib_buffer_t supplied by this fixture. */')+'\n'


def tcp_selected_fixture():
    source=(ROOT/'src/product/vpp/product_root_dns_adapter.inc').read_text()
    start=source.index('static int root_dns_tcp_selected(')
    opening=source.index('{',start)
    return source[start:source.index('\n}',opening)+2]+'\n'
