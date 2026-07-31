# IDA 9.4 全平台包

这里放的是 IDA 9.4 的全平台安装包、补丁文件和许可证生成脚本。

安装包在 [v9.4-installers](https://github.com/Yigods/ida94_b1/releases/tag/v9.4-installers) Release。补丁和脚本在仓库的 `kg_patch/` 目录。

## 目录说明

| 路径 | 内容 |
| --- | --- |
| `ida-pro_94_x64win.exe` | Windows x64 安装包（Release） |
| `ida-pro_94_armwin.exe` | Windows ARM 安装包（Release） |
| `ida-pro_94_x64linux.run` | Linux x64 安装包（Release） |
| `ida-pro_94_armlinux.run` | Linux ARM 安装包（Release） |
| `ida-pro_94_x64mac.app.zip` | macOS Intel 安装包（Release） |
| `ida-pro_94_armmac.app.zip` | macOS Apple Silicon 安装包（Release） |
| `kg_patch/x64win/` | Windows x64：`ida.dll`、`ida32.dll` |
| `kg_patch/x64linux/` | Linux x64：`libida.so`、`libida32.so` |
| `kg_patch/patch_ida94_armmac.py` | macOS ARM64 处理脚本 |
| `kg_patch/全平台注册机IDA94b1.py` | 许可证生成脚本，生成 `idapro.hexlic` |
| `misc/` | 其他 9.4 组件 |
| `SHA256SUMS` | 文件哈希 |

当前已整理并验证的补丁对应关系：

| 平台 | 可用处理方式 |
| --- | --- |
| Windows x64 | 替换 `ida.dll`、`ida32.dll` |
| Linux x64 | 替换 `libida.so`、`libida32.so` |
| macOS ARM64 | 使用 `patch_ida94_armmac.py` |
| Windows ARM、Linux ARM、macOS x64 | 只有安装包，未放对应补丁 |

不要把 x64 的 DLL/SO 替换到 ARM 版本，也不要把 9.4 的文件用于其他 IDA 版本。

## 先生成许可证

`全平台注册机IDA94b1.py` 只生成 `idapro.hexlic`，不修改 DLL、SO 或 dylib。它固定把文件写到当前目录。

默认信息：

```text
name : yigod
owner: yigod
email: oneyigod@gmail.com
```

在 IDA 安装目录里生成：

```bash
cd "IDA安装目录"
python3 /你的路径/kg_patch/全平台注册机IDA94b1.py
```

如果安装目录已经有许可证，先备份：

```bash
cp idapro.hexlic idapro.hexlic.bak
python3 /你的路径/kg_patch/全平台注册机IDA94b1.py
```

Windows 没有 Python 时，可以在任意有 Python 的机器上运行脚本，再把生成的 `idapro.hexlic` 复制到 IDA 安装目录。

## Windows x64：替换 DLL

下面以默认安装目录为例。先退出 IDA，并用 PowerShell **管理员身份**运行：

```powershell
$IDA = "C:\Program Files\IDA Professional 9.4"
$PATCH = "C:\Users\你的用户名\Downloads\ida94_b1\kg_patch\x64win"

Copy-Item "$IDA\ida.dll" "$IDA\ida.dll.bak"
Copy-Item "$IDA\ida32.dll" "$IDA\ida32.dll.bak"

Copy-Item "$PATCH\ida.dll" "$IDA\ida.dll" -Force
Copy-Item "$PATCH\ida32.dll" "$IDA\ida32.dll" -Force
Copy-Item "C:\Users\你的用户名\Downloads\idapro.hexlic" "$IDA\idapro.hexlic" -Force
```

如果在 IDA 安装目录生成许可证，最后一条可以省略。安装目录不是默认位置时，改 `$IDA` 即可。

恢复原始 DLL：

```powershell
Copy-Item "$IDA\ida.dll.bak" "$IDA\ida.dll" -Force
Copy-Item "$IDA\ida32.dll.bak" "$IDA\ida32.dll" -Force
```

## Linux x64：替换 SO

假设 IDA 安装在 `/opt/ida-pro-9.4`。先退出 IDA：

```bash
IDA=/opt/ida-pro-9.4
PATCH=/你的路径/ida94_b1/kg_patch/x64linux

cp "$IDA/libida.so" "$IDA/libida.so.bak"
cp "$IDA/libida32.so" "$IDA/libida32.so.bak"

cp "$PATCH/libida.so" "$IDA/libida.so"
cp "$PATCH/libida32.so" "$IDA/libida32.so"

cd "$IDA"
python3 /你的路径/ida94_b1/kg_patch/全平台注册机IDA94b1.py
```

没有写权限时，在命令前加 `sudo`。恢复：

```bash
cp "$IDA/libida.so.bak" "$IDA/libida.so"
cp "$IDA/libida32.so.bak" "$IDA/libida32.so"
```

## macOS Apple Silicon：脚本处理 dylib

适用于 Apple Silicon 的 IDA 9.4，例如：

```text
/Applications/IDA Professional 9.4.app
```

把 `kg_patch` 复制到 Mac 后运行：

```zsh
cd ~/Downloads/kg_patch

python3 patch_ida94_armmac.py \
  --app "/Applications/IDA Professional 9.4.app" \
  --in-place --apply --generate-license --sign
```

脚本会：

1. 检查 `libida.dylib`、`libida32.dylib` 是否为已验证的 ARM64 9.4 文件；
2. 备份为 `libida.dylib.bak` 和 `libida32.dylib.bak`；
3. 修改两个 dylib；
4. 在 `Contents/MacOS/` 写入 `idapro.hexlic`；
5. 只重签修改过的 dylib。

如果 App 被 macOS 标记为隔离文件：

```zsh
xattr -dr com.apple.quarantine "/Applications/IDA Professional 9.4.app"
```

不要执行 `codesign --deep`。需要手工重签时，只签这两个文件：

```zsh
MACOS="/Applications/IDA Professional 9.4.app/Contents/MacOS"
codesign --force --sign - --timestamp=none "$MACOS/libida.dylib"
codesign --force --sign - --timestamp=none "$MACOS/libida32.dylib"
```

恢复 macOS 原文件：

```zsh
MACOS="/Applications/IDA Professional 9.4.app/Contents/MacOS"
cp "$MACOS/libida.dylib.bak" "$MACOS/libida.dylib"
cp "$MACOS/libida32.dylib.bak" "$MACOS/libida32.dylib"
codesign --force --sign - --timestamp=none "$MACOS/libida.dylib"
codesign --force --sign - --timestamp=none "$MACOS/libida32.dylib"
```

## 检查文件

下载后可校验：

```bash
sha256sum -c SHA256SUMS
```

macOS 使用：

```zsh
shasum -a 256 -c SHA256SUMS
```

`SHA256SUMS` 也包含 Release 中的大安装包；把 Release 文件下载到仓库根目录后即可一起校验。
