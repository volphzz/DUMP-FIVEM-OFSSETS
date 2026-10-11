# Vxz F-DUMPER

A read-only Windows utility that scans the executable memory of a running FiveM/GTA process for configured byte patterns and exports candidate addresses in several source formats.

## Download

Download `Vxz-F-DUMPER-v1.0.0-windows-x64.zip` from the [latest release](https://github.com/volphzz/DUMP-FIVEM-OFSSETS/releases/latest). Extract the ZIP and run `Iniciar.cmd` while FiveM is running. Generated files are written to the `exports` folder beside the launcher.

The release binary is unsigned. Windows SmartScreen or antivirus software may show a warning; verify the release checksum before running it and only use it if you trust the source.

## Output and limitations

- Exports JSON, C++, C#, Rust, Cheat Engine table, and a CSV scan report.
- Values are RVAs relative to the game module base, not necessarily structure-field offsets.
- Pattern matches are candidates, not semantic validation. Missing or ambiguous signatures are omitted.
- Signatures are build-sensitive; compatibility with other FiveM/GTA builds is not guaranteed.
- The included validation record covers one FiveM build 3258 process. It does not establish compatibility with other builds.

## Build from source

Open `src/Vxz F-DUMPER.vcxproj` in Visual Studio 2022 with the C++ desktop workload and build `Release | x64`. The project uses C++20 and the v143 toolset. The executable is emitted to `bin/`.

## Safety

The scanner opens the target process for query/read access and does not write to its memory. Use only on software and systems you are authorized to inspect. This project is provided without warranty.

## Português

Utilitário Windows de leitura que procura padrões de bytes na memória executável de um processo FiveM/GTA em execução e exporta endereços candidatos em vários formatos.

Baixe `Vxz-F-DUMPER-v1.0.0-windows-x64.zip` na página de [releases](https://github.com/volphzz/DUMP-FIVEM-OFSSETS/releases/latest), extraia e execute `Iniciar.cmd` com o FiveM aberto. Os arquivos gerados ficam em `exports` ao lado do iniciador.

Os valores são RVAs relativos à base do módulo, não necessariamente offsets de campos de estruturas. Correspondências de padrões não confirmam a semântica do endereço. Assinaturas ausentes ou ambíguas são omitidas e a compatibilidade depende da build.
