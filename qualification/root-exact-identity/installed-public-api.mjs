// Thin composition of the repository's existing public API snapshot owner.
// CLI: node THIS SOURCE CONSUMER NEW_PROJECT NEW_REPORT
// The outer bounded driver separately executes the emitted compiler command and records settlement.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const [sourceArg, consumerArg, projectArg, outputArg, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0);
const source = fs.realpathSync(sourceArg), consumer = fs.realpathSync(consumerArg);
const project = path.resolve(projectArg), output = path.resolve(outputArg);
assert(!fs.existsSync(project) && !fs.existsSync(output));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const sourceRequire = createRequire(path.join(source, 'package.json'));
const consumerRequire = createRequire(path.join(consumer, 'package.json'));
const packageRoot = fs.realpathSync(path.dirname(consumerRequire.resolve('@openclaw/fs-safe/package.json')));
assert.equal(packageRoot, path.join(consumer, 'node_modules/@openclaw/fs-safe'));
const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json')));
const expected = JSON.parse(fs.readFileSync(path.join(source, 'test/public-api.json')));
fs.mkdirSync(project, { mode: 0o700 });
fs.writeFileSync(path.join(project, 'package.json'), '{"private":true,"type":"module"}\n', { flag: 'wx' });
fs.symlinkSync(path.join(consumer, 'node_modules'), path.join(project, 'node_modules'), 'dir');
const helper = path.join(source, 'scripts/public-api-surface.mjs');
const { inspectPublicApi, assertPublicApi } = await import(pathToFileURL(helper));
const previousCwd = process.cwd(); process.chdir(source);
let actual;
try { actual = inspectPublicApi({ packageName: pkg.name, packageSubpaths: Object.keys(pkg.exports), workdir: project }); assertPublicApi(actual); }
finally { process.chdir(previousCwd); }
assert.deepEqual(actual, expected);
for (const specifier of ['root-context', 'root-observed-path', 'root-walk'].flatMap(name => ['@openclaw/fs-safe/' + name, '@openclaw/fs-safe/dist/' + name + '.js'])) {
  assert.throws(() => consumerRequire.resolve(specifier), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
}
const compilerPackage = sourceRequire.resolve('typescript/package.json');
const compilerMetadata = JSON.parse(fs.readFileSync(compilerPackage));
const compiler = fs.realpathSync(path.resolve(path.dirname(compilerPackage), compilerMetadata.bin.tsc));
const nodeTypesPackage = sourceRequire.resolve('@types/node/package.json');
const typesRoot = path.dirname(path.dirname(fs.realpathSync(nodeTypesPackage)));
const configuration = { compilerOptions: { strict: true, noUncheckedIndexedAccess: true, noEmit: true,
  skipLibCheck: false, esModuleInterop: true, module: 'NodeNext', moduleResolution: 'NodeNext',
  target: 'ES2022', lib: ['ES2023', 'ESNext.Disposable'], types: ['node'], typeRoots: [typesRoot] },
  files: ['public-api-surface.ts'] };
const configFile = path.join(project, 'tsconfig.json'); fs.writeFileSync(configFile, JSON.stringify(configuration, null, 2) + '\n', { flag: 'wx' });
const result = { schema: 1, snapshotPassed: true, privateSubpathsDenied: true, source, consumer, packageRoot,
  packageExports: pkg.exports, packageJsonSha256: hash(path.join(packageRoot, 'package.json')),
  expectedSnapshotSha256: hash(path.join(source, 'test/public-api.json')), helperSha256: hash(helper), actual,
  typecheck: { executed: false, compiler, compilerSha256: hash(compiler), compilerVersion: compilerMetadata.version,
    nodeTypesPackageSha256: hash(nodeTypesPackage), configuration: configFile, configurationSha256: hash(configFile),
    probe: path.join(project, 'public-api-surface.ts'), probeSha256: hash(path.join(project, 'public-api-surface.ts')),
    command: [process.execPath, compiler, '-p', configFile] } };
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify(result));
