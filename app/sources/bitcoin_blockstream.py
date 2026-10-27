from __future__ import annotations

from app.sources.bitcoin_mempool import BitcoinEsploraSource


class BitcoinBlockstreamSource(BitcoinEsploraSource):
    name = "blockstream_esplora"
    api_base = "https://blockstream.info/api"
