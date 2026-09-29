#!/usr/bin/env python3
"""Install checksum-pinned task tools without creating a global tool cache."""
import base64
import hashlib
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, digest, private_layout, require, run, write


def main():
    layout = private_layout()
    output = layout['evidence'] / 'tooling'
    output.mkdir()
    for name in ['tooling', 'cargo', 'rustup', 'pnpm', 'cache', 'pnpmStore', 'npmCache', 'clangCache']:
        layout[name].mkdir(parents=True, exist_ok=True)
    archives = [
        ('node', 'https://nodejs.org/dist/v24.21.0/node-v24.21.0-darwin-arm64.tar.gz',
         'sha256', 'bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057'),
        ('pnpm', 'https://registry.npmjs.org/@pnpm/exe.darwin-arm64/-/exe.darwin-arm64-12.4.2.tgz',
         'sha512', 'A0WDo8iErfZBXgrLseQxw8i8Y9ctUpOEl/Uu+cubnTzpD8tT9ykIB548L8YTM2WD4OS+ZOHSxy8aGZcvKq8PaQ=='),
    ]
    for name, url, algorithm, expected in archives:
        archive = output / (name + '.tgz')
        run(output, name + '-download', ['/usr/bin/curl', '--fail', '--show-error', '--silent', '--location',
            '--max-time', '180', '--output', archive, url], timeout=190)
        hashed = hashlib.new(algorithm, archive.read_bytes()).digest()
        actual = hashed.hex() if algorithm == 'sha256' else base64.b64encode(hashed).decode()
        require(actual == expected, name + ' archive integrity mismatch')
        destination = layout['tooling'] / name
        destination.mkdir(exist_ok=True)
        run(output, name + '-extract', ['/usr/bin/tar', '-xzf', archive, '-C', destination], timeout=60)
        write(output / (name + '-archive.json'), dict(url=url, algorithm=algorithm, expected=expected,
              sha256=digest(archive), destination=str(destination)))
    node = layout['tooling'] / 'node/node-v24.21.0-darwin-arm64/bin/node'
    pnpm = layout['pnpm'] / 'package/pnpm'
    require(node.resolve().is_relative_to(layout['root']) and pnpm.resolve().is_relative_to(layout['root']), 'tool payload escaped')
    env = dict(PATH=os.pathsep.join([str(node.parent), str(pnpm.parent), os.environ['PATH']]))
    run(output, 'rust-install', ['rustup', 'toolchain', 'install', '1.98.1', '--profile', 'minimal',
        '--component', 'llvm-tools-preview', '--target', 'wasm32-unknown-unknown'], extra_env=env, timeout=900)
    run(output, 'archive-compiler-install', [node, layout['harness'] / '.github/actions/setup-archive-llvm/install.mjs'],
        extra_env=dict(env, RUNNER_TEMP=str(layout['tooling'])), timeout=600)
    with Path(os.environ['GITHUB_PATH']).open('a') as stream:
        stream.write(f'{node.parent}\n{pnpm.parent}\n')
    write(output / 'complete.json', dict(node=str(node), nodeSha256=digest(node), pnpm=str(pnpm), pnpmSha256=digest(pnpm)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        write(Path(os.environ['EVIDENCE_ROOT']) / 'bootstrap-failure.json', dict(error=str(error), disposition='incomplete; no retry'))
        raise
