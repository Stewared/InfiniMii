# Resource notice

The files under `assets/` are data extracted from Tomodachi Life and are not
covered by InfiniMii's project license. The native renderer sources were copied
from the local Decomp and ResearchingTomodachi codebases named in the renderer
request and do not carry a separate license grant here. Keep this runtime
private unless you have independently confirmed that you may redistribute it.

`assets/FFLResHigh.dat` was copied into this self-contained runtime from the
provided InfiniMii workspace resource. The local FFL-Testing extension
interprets the otherwise-unused header word at `+0x0c` as
`m_ExpandedBufferSize`; this file's value is the source-defined AFL-high size
(`0x0239d5e0`), so it uses that implementation's linear AFL layout. Its
SHA-256 is
`5d45a6ab4174cf448129b1f9c8ab0fb5c7ac15e544f8f64dff8959b41bb5f7db`.

The `vendor/miniz` files are from miniz 3.1.2
(https://github.com/richgel999/miniz/tree/3.1.2), licensed under the MIT
license. The upstream license is preserved at `vendor/miniz/LICENSE`.

The `vendor/nintexutils` files are the minimal GX2 surface/address subset
copied from
`Decomp/reference_repos/FFL-Testing/ninTexUtils`, the implementation used by
the local supported FFL code to untile Wii U FFL resources. That source is
GPL-3.0; its license is preserved at `vendor/nintexutils/LICENSE`.
