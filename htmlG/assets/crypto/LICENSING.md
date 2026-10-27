# Donation method artwork

Checked on 2026-10-26. These files identify the network or service next to a
donation method. They do not imply sponsorship, endorsement, affiliation,
ownership of a mark, or a blockchain attribution finding. Copyright permissions
and trademark rights are separate. This directory does not claim that the marks
are licensed under Gansar's source-code licence.

| Requested file | Artwork origin and local-use basis | Representation |
| --- | --- | --- |
| `ton.svg` | [Official TON media page](https://ton.org/media/) offers resources for identifying the TON blockchain. Its own favicon link supplies this [official mark](https://ton.org/assets/favicon.svg). Used only to identify the TON network; no broader open artwork or trademark licence is asserted. | Unchanged native SVG, including its original colours and proportions. |
| `tron.svg` | The [official TRON resources page](https://tron.network/resources/?lng=en) offers a downloadable logo media kit and visual identity guide. Taken from that [official ZIP](https://tron.network/static/doc/%E6%A0%87%E5%BF%97%E4%B8%8E%E5%9B%BE%E5%BD%A2%E6%8C%87%E5%8D%97.zip), nested SVG kit, `LOGO ICON/TRON LOGO ICON RED.svg`. Used as an accurate network identifier; no blanket copyright/trademark licence is asserted. | Unchanged native SVG; the white background is part of the supplied artwork, not an added frame. |
| `bitcoin.svg` | [Bitboy's original creator post](https://bitcointalk.org/index.php?topic=1631.0) and [vector release](https://bitcointalk.org/index.php?topic=1756.0) dedicate the work to the public domain and permit local hosting. The standalone symbol is the [download supplied by Bitcoin Design](https://bitcoin.design/guide/getting-started/visual-language/). Bitcoin has no single brand authority; this is the recognised Bitboy symbol, not an assertion of an official Bitcoin foundation. | Unchanged native SVG from the linked symbol download; no wordmark or redistributed font. |
| `ethereum.svg` | **Not bundled.** [Ethereum assets](https://ethereum.org/assets/) were found, but the [current terms](https://ethereum.org/terms-of-use) distinguish the CC-BY-4.0 licence for non-code content from marks requiring prior written permission. A separate applicable permission was not confirmed. | Keep the Ethereum name and full donation address visible. Use the text fallback until a permitted genuine asset is supplied. |
| `solana.svg` | The [official branding page](https://solana.com/branding) supplies this [native logomark SVG](https://solana.com/src/img/branding/solanaLogoMark.svg) for website/marketing identification subject to its brand guidelines. Preserve the artwork and clear space; do not imply Foundation affiliation, combine it into a new mark, recolour, stretch, add effects, or use it as Gansar branding. | Unchanged native SVG, with the original built-in brand gradient. |
| `cryptobot.svg` | **Not bundled.** [Crypto Bot](https://send.tg) and the [official resources article](https://help.send.tg/en/articles/9820327-links-to-official-resources) establish service identity, but no applicable reusable artwork permission was confirmed. Direct retrieval of the help article returned HTTP 403; search-accessible article text is not a licence. | Keep the CryptoBot name and exact Telegram donation link visible. Use the text fallback rather than an invented or unverified SVG. |
| `xrocket.svg` | The [official xRocket brand kit](https://xrocket.exchange/brand-kit) offers brand resources and usage guidance. The embedded image is its [official 32 px favicon](https://xrocket.exchange/img/favicon-32x32.png), unchanged and proportionally displayed. Follow the kit's restrictions on shadows, outlines, stretching and picture-frame use; no broader licence is asserted. | A real SVG document embedding the original PNG as a data URI. **This is raster artwork in an SVG container, not a vector conversion or tracing.** The PNG matches the already bundled, verified service icon byte for byte. |

`BRAND_ASSETS.json` records all seven requested paths, the two deliberate text
fallbacks, source URLs, representations, dimensions, sizes, safety results and
SHA-256 values. The five supplied SVG documents total 7,120 bytes. They contain
no scripts, event handlers, external references or external font dependencies.
They require no network connection at runtime. Scale proportionally using the
existing image layout; do not apply colour filters or decorative effects.

The seven pre-existing PNG/JPG files supplied in this folder are preserved
byte for byte. Their presence is not a verified copyright/trademark permission,
and they are not silently promoted to production fallbacks when a documented
SVG is absent.

Small retrieval and integrity evidence is kept at
`validation/about_composition_20261026/logos/`. Archives were processed in
memory and not retained on disk. Only the selected compact artwork was saved.
