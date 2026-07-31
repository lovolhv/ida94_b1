# ida94_b1

IDA 9.4 analysis and patch package.

## Repository contents

- [`kg_patch/`](kg_patch/README): macOS ARM64 patch helper, license material, and x64 comparison samples.
- [`misc/`](misc/): auxiliary 9.4 artifacts.
- `SHA256SUMS`: hashes for every archived artifact and repository file.

The six IDA installer packages exceed GitHub's 100 MiB Git-file limit. They are preserved as assets of the private GitHub Release **`v9.4-installers`**, rather than being omitted.

## 使用前提

- 目标为 **IDA Professional 9.4 Apple Silicon（ARM64）**；脚本会拒绝 x86 或不匹配的版本。
- macOS 需要自带的 `python3` 与 `codesign`。
- 请保留原始安装包或 `.bak` 备份，以便回退。

> 不要对整个 App 使用 `codesign --deep`。App 内文档目录含有 `.md.in` 文件，递归签名会出现 `bundle format unrecognized`；本项目只重签被修改的两个 dylib。

## 教程一：macOS ARM64 一键原地处理（推荐）

适合已把 IDA 9.4 安装到默认路径的情况。先下载仓库或仅复制其中的 `kg_patch` 目录到 Mac，例如 `~/Downloads/kg_patch`。

```zsh
cd ~/Downloads/kg_patch

python3 patch_ida94_armmac.py \
  --app "/Applications/IDA Professional 9.4.app" \
  --in-place --apply --generate-license --sign
```

该命令会依次完成：

1. 校验 `libida.dylib` 和 `libida32.dylib` 均为匹配的 IDA 9.4 ARM64 文件；
2. 在原目录创建 `libida.dylib.bak`、`libida32.dylib.bak`；
3. 修改两个 dylib，并在 `Contents/MacOS/` 生成默认资料为 `yigod` 的 `idapro.hexlic`；
4. 使用 ad-hoc 签名重新签署两个修改后的 dylib。

如 App 来自浏览器下载，再移除隔离属性并启动：

```zsh
xattr -dr com.apple.quarantine "/Applications/IDA Professional 9.4.app"
open "/Applications/IDA Professional 9.4.app"
```

若需要确认签名状态：

```zsh
codesign --verify --verbose=2 \
  "/Applications/IDA Professional 9.4.app/Contents/MacOS/libida.dylib"
codesign --verify --verbose=2 \
  "/Applications/IDA Professional 9.4.app/Contents/MacOS/libida32.dylib"
```

## 教程二：先生成独立输出，再手工替换

适合希望先保存处理结果、检查后才影响已安装 App 的情况。以下命令不会立刻修改 `/Applications` 中的文件。

```zsh
cd ~/Downloads/kg_patch

python3 patch_ida94_armmac.py \
  --input-dir "/Applications/IDA Professional 9.4.app/Contents/MacOS" \
  --out-dir ./mac_arm_patched \
  --apply --generate-license
```

检查 `mac_arm_patched/` 中是否包含：

```text
libida.dylib
libida32.dylib
idapro.hexlic
```

确认后执行替换和签名：

```zsh
APP="/Applications/IDA Professional 9.4.app"
MACOS="$APP/Contents/MacOS"

# 手工备份原始文件
cp "$MACOS/libida.dylib" "$MACOS/libida.dylib.bak"
cp "$MACOS/libida32.dylib" "$MACOS/libida32.dylib.bak"

# 替换两个 dylib 和许可证
cp ./mac_arm_patched/libida.dylib "$MACOS/"
cp ./mac_arm_patched/libida32.dylib "$MACOS/"
cp ./mac_arm_patched/idapro.hexlic "$MACOS/"

# 仅重签被修改的库
codesign --force --sign - --timestamp=none "$MACOS/libida.dylib"
codesign --force --sign - --timestamp=none "$MACOS/libida32.dylib"

xattr -dr com.apple.quarantine "$APP"
open "$APP"
```

如需恢复，关闭 IDA 后执行：

```zsh
APP="/Applications/IDA Professional 9.4.app"
MACOS="$APP/Contents/MacOS"

cp "$MACOS/libida.dylib.bak" "$MACOS/libida.dylib"
cp "$MACOS/libida32.dylib.bak" "$MACOS/libida32.dylib"
codesign --force --sign - --timestamp=none "$MACOS/libida.dylib"
codesign --force --sign - --timestamp=none "$MACOS/libida32.dylib"
```

更多参数和特征校验逻辑参见 [`kg_patch/README`](kg_patch/README)。

## 教程三：单独使用许可证生成器

`kg_patch/全平台注册机IDA94b1.py` 是未混淆的 Python 源码，只负责在**当前工作目录**生成 `idapro.hexlic`，不会修改任何二进制文件。

当前默认许可证信息为：

```text
name : yigod
owner: yigod
email: oneyigod@gmail.com
```

在 `kg_patch` 目录执行：

```zsh
cd ~/Downloads/kg_patch
python3 全平台注册机IDA94b1.py
```

成功后会在当前目录写入 `idapro.hexlic` 并打印签名。该脚本固定写入当前目录；若要直接生成到已安装的 IDA 目录，使用：

```zsh
cd "/Applications/IDA Professional 9.4.app/Contents/MacOS"
python3 ~/Downloads/kg_patch/全平台注册机IDA94b1.py
```

如果该目录已有许可证，先保留备份：

```zsh
cd "/Applications/IDA Professional 9.4.app/Contents/MacOS"
cp idapro.hexlic idapro.hexlic.bak
python3 ~/Downloads/kg_patch/全平台注册机IDA94b1.py
```
