"""Build a concrete, synthetic semantic example without running code or an API."""

import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from fixtures import request  # noqa: E402


def build():
    payload = request()
    target = hashlib.sha1(b"synthetic-limit-none-zero-fixture-v1").hexdigest()
    payload["mode"] = "model"
    payload["context"].update(
        title="合成语义样例：修复分页 limit 的零值丢失",
        description="仅合成材料；未执行代码或测试。检查 None 默认值、合法零值和负数拒绝的边界。",
        target_commit=target,
    )
    user = """修复 pagination.py 的 normalize_limit(value)：现有 value or 25 把合法 0 错误变成 25。
验收 A1：None 返回默认分页数量 25。
验收 A2：0 必须原样返回 0，表示调用方明确请求空页。
验收 A3：正整数 1 和 30 原样返回。
验收 A4：负数 -1 继续抛 ValueError('limit must be non-negative')，不得改变现有拒绝行为。
仅改这个函数的 None 默认值判断，并在 tests/test_pagination.py 添加以上断言；不要修改其他 API 或增加依赖。
测试设计必须覆盖修复前的 0 反例和 None/正数/负数回归；显式说明默认 pytest 配置及 mock/skip 使用。
本次材料为合成示例，未实际执行测试；请把运行核验保留未核查。"""
    source = """File: pagination.py
def normalize_limit(value):
    if value is None:
        return 25
    if value < 0:
        raise ValueError("limit must be non-negative")
    return value
"""
    test = """File: tests/test_pagination.py
import pytest
from pagination import normalize_limit

def test_none_defaults_to_25():
    assert normalize_limit(None) == 25  # A1

def test_zero_stays_zero():
    assert normalize_limit(0) == 0  # A2; old implementation returned 25

@pytest.mark.parametrize("value", [1, 30])
def test_positive_limit_preserved(value):
    assert normalize_limit(value) == value  # A3

def test_negative_limit_rejected():
    with pytest.raises(ValueError, match="^limit must be non-negative$"):
        normalize_limit(-1)  # A4
"""
    diff = """Synthetic complete target diff; two text files only, no omitted or binary patches.
diff --git a/pagination.py b/pagination.py
--- a/pagination.py
+++ b/pagination.py
@@ -1,4 +1,6 @@
 def normalize_limit(value):
+    if value is None:
+        return 25
     if value < 0:
         raise ValueError("limit must be non-negative")
-    return value or 25
+    return value
diff --git a/tests/test_pagination.py b/tests/test_pagination.py
new file mode 100644
--- /dev/null
+++ b/tests/test_pagination.py
@@ -0,0 +1,16 @@
+import pytest
+from pagination import normalize_limit
+
+def test_none_defaults_to_25():
+    assert normalize_limit(None) == 25  # A1
+
+def test_zero_stays_zero():
+    assert normalize_limit(0) == 0  # A2; old implementation returned 25
+
+@pytest.mark.parametrize("value", [1, 30])
+def test_positive_limit_preserved(value):
+    assert normalize_limit(value) == value  # A3
+
+def test_negative_limit_rejected():
+    with pytest.raises(ValueError, match="^limit must be non-negative$"):
+        normalize_limit(-1)  # A4
"""
    context = f"""合成材料清单，不是执行证明。
源代码和完整 diff 的合成目标版本：{target}；这个 SHA 仅用于版本绑定测试，不声称真实 Git 提交。
目标环境计划：CPython 3.12、Linux x86_64、pytest 8.3；源码使用标准库，测试仅依赖 pytest。
测试配置计划：使用 pytest 默认配置，没有 pytest.ini/pyproject pytest 配置覆盖。
测试范围计划：python -m pytest -q tests/test_pagination.py；本次没有运行此命令。
验收到断言映射：A1->test_none_defaults_to_25；A2->test_zero_stays_zero；A3->test_positive_limit_preserved[1/30]；A4->test_negative_limit_rejected。
前置：从包含 pagination.py 的项目根目录导入；0 是明确负例/修复回归，None 和正数是正常回归，负数验证保留拒绝契约。
mock/skip 说明：测试源码无 mock、无 skip、无 xfail，也不依赖网络或外部服务。
当前合成项目 SOP development v1，digest={payload['sop']['digest']}；六章文本完整附于 sop 字段。
没有运行输出、构建产物、人工复核或最终实例证据。"""

    def row(sid, kind, content, version=False):
        result = {"id": sid, "kind": kind, "content": content,
                  "locator": {"kind": "manual", "note": "Synthetic semantic fixture: " + sid}}
        if version:
            result["version_id"] = target
        return result

    payload["sources"] = [row("user", "user_message", user), row("diff", "commit_diff", diff, True),
                          row("code", "source", source, True), row("test", "source", test, True),
                          row("context", "context", context)]
    return payload


if __name__ == "__main__":
    path = ROOT / "examples" / "model-request.json"
    path.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
