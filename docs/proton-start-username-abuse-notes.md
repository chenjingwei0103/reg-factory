# Proton /start 用户名输入风控机制与剪贴板绕过实测记录

日期: 2026-11-02
操作人: Ethan

## 1. 核心风控根因定位 (Root Cause Analysis)

通过 REA 分析 Proton `/start` 页面安全脚本（`webpackChunkabuse` 与 challenge v4）发现：
1. **DOM 与事件上报架构**：
   - 宿主页面的 `#username` 为不可见的离屏镜像节点（坐标在屏幕外 `x: -967, y: -566`）。
   - 真正承载输入的是子 Iframe：`https://account-api.proton.me/challenge/v4/html?Type=0&Name=email`。
   - 子 Iframe 绑定了全局 `keydown`、`input` 和 `click` 监听器，每输入一个字符都会向父页面和后台上报结构化按键轨迹：
     `{ type: "event", payload: { type: "keydown", id: "username", key: ... } }` 与 `{ type: "input", value: ... }`。
2. **为何 CDP / Native 单字击键必被 422 Abuse 拦截**：
   - 脚本中若包含 `Ctrl+A -> Backspace`、预热字符（如输入 `"a"` 再退格）、或高频/固定节拍的单个虚拟键合成事件，后台风控模型会识别其机器击键特征（无真实生物微抖动、无系统级输入法介入）；
   - 最终在提交进入 `/api/core/v4/users` 时直接触发风控拦截，报 `422 (We are detecting potentially abusive traffic)`。

## 2. 绕过方案与实测验证 (Verification & Fix)

1. **绕过原理**：
   - 使用系统剪贴板（Win32 Clipboard）单次写入用户名，然后执行单次 `Ctrl+V`（或利用剪贴板粘贴模式）。
   - 剪贴板粘贴只触发单次整体 `input` 事件，完全避开了单字按键序列和高频退格特征的上报，与真实用户复制粘贴完全一致。
2. **实操验证对比**：
   - **w4 窗口**：使用 CDP 逐步击键输入用户名 -> 提交后 100% 出现红色 Abuse 422 拦截。
   - **w3 窗口**：采用剪贴板整段粘贴用户名 -> 提交后顺利放行，成功弹出拼图验证码（Human Verification CAPTCHA），无任何 Abuse 提示。

## 3. 项目落地与维护规范

1. `/start` 流程用户名输入必须默认使用 `clipboard_paste` / 剪贴板模式，彻底移除任何预热击键及循环单字模拟。
2. 保持纯净环境，不向页面注入篡改 Navigator 属性的 hook，全流程依靠 Roxy 原生指纹。
