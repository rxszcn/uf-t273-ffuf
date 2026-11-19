# 交付说明：请求构造多关键词替换的确定性收敛

## 1. 背景与缺陷定位

授权演练平台的请求审计要求同一命令重复构造的请求完全可复现。沿请求构造链路 `Job.runTask` / `Job.calibrationRequest` / `printSearchResults` → `SimpleRunner.Prepare` 往下读，缺陷锚定在 `pkg/runner/simple.go` 的 `Prepare`：

```go
for keyword, inputitem := range input {           // map 遍历，顺序随机
    req.Url = strings.ReplaceAll(req.Url, keyword, string(inputitem))
    // Method / Headers(名+值) / Data 同样逐关键词串行 ReplaceAll
}
```

两个机制叠加导致同一输入构造结果不唯一：

1. **随机处理序**：`input` 是 `map[string][]byte`，Go 的 map 迭代顺序每次运行随机化，多关键词的替换先后不固定。
2. **串行回扫级联**：每轮 `ReplaceAll` 都对“上一轮替换产生的文本”重新扫描。当某关键词的载荷值字面含另一关键词名（如 `FUZZ → "W2-x"`，另有 `W2`）时，先替换 `FUZZ` 再替换 `W2` 会把载荷里的 `W2` 二次吞掉；反序则载荷原样保留。两种形态的占比随 map 迭代漂移。

此外，旧实现在每个关键词轮次内都对头部名做一次 `CanonicalMIMEHeaderKey`，使头部名在替换中途被规范化，叠加随机序后，连“载荷不含关键词字面量”的无重叠对照输入也会出现两种构造结果（实测见 §5）。

滚动升级期新旧扫描节点并行出量、网关超时重发、审计侧季度归档重放，都依赖 `Prepare` 的确定性；上述漂移使审计与取证回放无法复现原始请求。

## 2. 替换语义与边界取舍（设计决定及理由）

新语义在仓库既有 `varsReplacer`（preflight 变量替换）已确立的模式上统一，理由是该模式已被 `TestSubstitutionDeterministic` 锁定，团队已有共识：

- **单遍同时替换，不回扫替换产物**。一次 `strings.Replacer` 同时持有全部“关键词名 → 载荷值”对，对源串做一次扫描。替换写入的文本不再参与后续匹配，因此载荷值即使字面包含另一关键词名也原样保留，杜绝二次展开与级联。
- **关键词名确定性排序：最长名优先，等长按字典序**。当两个关键词名存在前缀重叠时，每个位置由最长匹配名胜出；`strings.Replacer` 内部本就按最长匹配解析，显式排序让构造结果与 map 迭代序彻底解耦，并使排序规则可在文档与代码中直接陈述。
- **四个面同一替换语义**。同一个 `*strings.Replacer` 实例分别作用于 Method、头部名、头部值、URL、Data 体，不存在面与面之间的语义差。
- **头部名边界**：先对模板头部名整体做一次替换，再做一次 `CanonicalMIMEHeaderKey` 规范化（旧实现是每个关键词轮次规范化一次）。头部值不做规范化，只做替换。两个不同模板头部替换后规范化为同一键时，按模板头部名排序后的固定顺序决定保留者，避免 map 遍历导致的碰撞幸存者漂移。
- **不引入回扫级联**：所有面都只经过单遍 replacer，替换产生的文本不会被任何关键词规则再次扫描。输入 map 以关键词名为键，即使两个提供器同名，每个名称也只以一个值进入 replacer，不存在重复 old-string 风险。
- **单关键词 / 无重叠值场景与现状完全一致**：单关键词时单遍 replacer 与单次 `ReplaceAll` 等价；无重叠多关键词时，Method/URL/Data/头部值的输出与旧实现逐字节相同；唯一可观察差异出现在“头部名内含小写关键词名”这一旧实现本身就顺序不确定的边角（旧实现两种形态都可能产生，新实现固定为单遍结果，属于缺陷修复而非回归），并由对照用例锁定。

`Prepare` 与 preflight 的 `varsReplacer` 现共用底层 helper `deterministicReplacer`，保证两条替换路径语义一致。`pkg/filter/regex.go` 中 `-mr/-fr` 正则模式构造存在同构的 map 串行替换，但它属于响应匹配环节、不参与请求构造与请求审计，不在本题“请求构造确定性”范围内，本次不改动，仅在此登记边界。

## 3. 改动面与题面要求逐条对照

| # | 题面要求 | 落点 | 落实方式 |
|---|----------|------|----------|
| 1 | 同一输入重复构造结果唯一 | `pkg/runner/simple.go` `Prepare`、新增 `inputReplacer`/`deterministicReplacer` | 单遍 `strings.Replacer` + 关键词名确定性排序，消除 map 随机序 |
| 2 | 载荷值不被二次展开 | 同上 | `strings.Replacer` 单遍同时替换，替换产物不回扫 |
| 3 | Method/头部/URL/数据体四面同一替换语义 | `Prepare` | 四面共用同一 replacer 实例 |
| 4 | 关键词出现在头部名与头部值两种位置的替换边界 | `Prepare` 头部重建段 | 头部名单遍替换后一次规范化；头部值仅替换；碰撞按排序固定 |
| 5 | 替换不得引入对替换产生文本的回扫级联 | `deterministicReplacer` | 单遍替换，无二次扫描 |
| 6 | 单关键词与无重叠值场景构造结果与现状完全一致 | `simple_test.go` 对照用例 | `TestPrepare_NoOverlapControlUnchanged` 锁定逐字节一致 |
| 7 | 三类断言补入 `pkg/runner` 既有 SimpleRunner 测试所在文件，框架/断言形态照旧，既有测试保持通过 | `pkg/runner/simple_test.go` | 沿用现有 `testing` + `t.Errorf/Fatalf` 表驱动风格，未引入新框架 |
| 8 | README 关键词适用位置与多词典用法随新语义一致 | `README.md` | 更新 Usage 适用位置（含方法、头部名/值），新增 “Multi-wordlist substitution” 小节与目录锚点 |
| 9 | 交付文档登记改动面与逐条对照、记录两组证据 | 本文件 | 见 §3、§5 |
| 10 | 快照环境零外部依赖复现 | 验证程序与 `go test` | 纯标准库 + 仓内包，无网络/无外部服务 |
| 11 | 验收以 `go test ./...` 零失败为准 | 全仓测试 | 见 §4；另修复一个阻断零失败的预存 Windows golden 行尾问题（见 §6） |

实际代码/文档改动文件：

- `pkg/runner/simple.go`：重写 `Prepare` 替换段；抽出 `deterministicReplacer`，`varsReplacer` 改为复用它；新增 `inputReplacer`。
- `pkg/runner/simple_test.go`：新增三类断言（构造唯一性、载荷保留形态、无重叠对照）及只读辅助函数。
- `README.md`：关键词适用位置与多词典确定性替换语义说明。
- `.gitattributes`（新增）：固定 `testdata/*.golden` 为 LF，理由见 §6。

## 4. 验收命令最终读数

命令：`go test -count=1 ./...`（禁用测试缓存），本机 `go version go1.27.4 windows/amd64`。

最终读数（12 个包全部 `ok`，0 个 FAIL）：

```
ok  	github.com/ffuf/ffuf/v2	0.799s
ok  	github.com/ffuf/ffuf/v2/pkg/engine	2.054s
ok  	github.com/ffuf/ffuf/v2/pkg/ffuf	0.995s
ok  	github.com/ffuf/ffuf/v2/pkg/filter	1.046s
ok  	github.com/ffuf/ffuf/v2/pkg/input	0.826s
ok  	github.com/ffuf/ffuf/v2/pkg/interactive	0.855s
ok  	github.com/ffuf/ffuf/v2/pkg/output	0.991s
ok  	github.com/ffuf/ffuf/v2/pkg/runner	2.766s
ok  	github.com/ffuf/ffuf/v2/pkg/scraper	0.784s
ok  	github.com/ffuf/ffuf/v2/pkg/testtarget	1.483s
ok  	github.com/ffuf/ffuf/v2/test/e2e	3.825s
ok  	github.com/ffuf/ffuf/v2/test/integration	6.264s
```

新增三类断言单独读数（`go test -count=1 -v -run TestPrepare_ ./pkg/runner/`）：

```
--- PASS: TestPrepare_OverlappingValueConstructionIsUnique
--- PASS: TestPrepare_PayloadKeepsLiteralForm
--- PASS: TestPrepare_NoOverlapControlUnchanged/single_keyword
--- PASS: TestPrepare_NoOverlapControlUnchanged/non-overlapping_dual_dictionaries
```

## 5. 构造输入下实测读数（改动前 vs 改动后）

读数口径：对同一构造输入重复构造 200 次，统计 **不同构造结果数** 与 **载荷保留形态** 两项。验证程序在仓库外独立目录，通过 `replace` 指向本仓调用真实 `SimpleRunner.Prepare`，仅用标准库与仓内包，无网络、无外部服务。改动前读数用 `git stash` 临时切回旧实现采集，随后恢复。

### 构造输入 A：自造双词典重叠值最小请求模板

- 关键词/载荷：`FUZZ → "W2-x"`（载荷字面含另一关键词名 `W2`），`W2 → "second"`
- 模板（四面全覆盖）：Method `GEFUZZT`；URL `https://example.org/a/FUZZ/b/W2`；Data `body=FUZZ&w=W2`；头部 `X-FUZZ-Name: val-FUZZ-W2`

| 读数 | 改动前（旧实现，200 次） | 改动后（新实现，200 次） |
|------|--------------------------|--------------------------|
| 不同构造结果数 | **2**（占比漂移，本次 167:33） | **1**（200/200 同一结果） |
| 载荷保留形态 | 形态①载荷被二次吞掉：`.../a/second-x/b/second`、Method `GEsecond-xT`、头部名 `X-Second-X-Name`；形态②载荷保留：`.../a/W2-x/b/second`、Method `GEW2-xT`、头部名 `X-Fuzz-Name` | 唯一形态，载荷原样保留：Method `GEW2-xT`；URL `https://example.org/a/W2-x/b/second`；Data `body=W2-x&w=second`；头部 `X-W2-X-Name: val-W2-x-second` |

要点：新形态中载荷 `W2-x` 在 Method/URL/Data/头部名/头部值五处均原样保留，仅独立的 `W2` 标记被替换为 `second`。

### 构造输入 B：无重叠对照模板

- 关键词/载荷：`PARAM → "id"`、`VAL → "42"`（载荷不含任何关键词字面量）
- 模板：Method `POST`；URL `https://example.org/?PARAM=VAL`；Data `PARAM=VAL`；头部 `X-PARAM: VAL`

| 读数 | 改动前（旧实现，200 次） | 改动后（新实现，200 次） |
|------|--------------------------|--------------------------|
| 不同构造结果数 | **2**（本次 174:26，头部名在 `X-Id` 与 `X-Param` 间漂移） | **1**（200/200 同一结果） |
| 构造结果 | 两种头部名形态并存 | Method `POST`；URL `https://example.org/?id=42`；Data `id=42`；头部 `X-Id: 42` |

要点：对照组在新实现下构造结果唯一；其 URL/Data/头部值与旧实现的“正确形态”逐字节一致，仅头部名收敛为单遍替换后的规范化结果，印证 §2 的兼容性承诺。

### 复现方式（零外部依赖）

仓内断言：

```
go test -count=1 -run TestPrepare_ ./pkg/runner/
```

独立构造读数程序（仓库外目录，`go.mod` 用 `replace` 指向本仓，`go run .` 即可，无网络请求）：输入 A/B 与上述口径一致，输出“不同构造结果数”和唯一构造结果全文。

## 6. 预存 Windows golden 失败的处置（与本缺陷无关，但为满足零失败验收）

改动前在干净工作树运行 `go test ./...`，根包 `TestCharacterization_HelpGolden` 即失败。定性：仓库索引中 `testdata/help.golden` 为 LF，本机 `core.autocrlf=true` 把工作树副本转成 CRLF，而 Go 运行时帮助输出恒为 LF，测试按字符串精确比较故失败；正文内容逐字节相同，仅行尾（及末尾一个换行）差异。该失败与请求构造改动无关（`git stash` 撤回全部代码改动后仍失败）。

处置：新增 `.gitattributes`，固定 `testdata/*.golden eol=lf`，并把工作树 golden 规范化为 LF。不改测试比较逻辑、不改 golden 正文内容，使该用例在任意平台/任意 `autocrlf` 设置下结论一致。配置类 golden 测试在 Windows 本就 `t.Skip`，一并固定仅为保持目录行尾策略统一。

## 7. 范围外登记

- `pkg/filter/regex.go` 的 `-mr/-fr` 模式构造存在同构 map 串行替换，属响应匹配而非请求构造，未改动。
- `pkg/runner/simple.go` 中 preflight/postflight 的 `applyVars`/`varsReplacer` 本就是确定性单遍实现，本次仅将其构造逻辑下沉为共享 helper，外部行为不变（既有 `TestSubstitutionDeterministic` 等全部通过）。
