/**
 * 新韩剧网 (9hanju.com) TVBox / FreeBox JS Spider
 * ================================================
 * 站点：https://www.9hanju.com/
 * 说明：韩剧、韩国电影、韩国综艺
 *
 * 已实现: init, home, homeVod, category, detail, play, search
 * 必须实现: init, home, category, detail, play, search
 *
 * ⚠️ 关于模块导入（重要）：
 * ./lib/cat.js 提供的模块名为 Crypto（对应 crypto-js 库），
 * 不是 CryptoJS。错误的导入名会导致 ReferenceError。
 * 参考：code 模组对照表 —— Crypto → crypto-js
 */
import { load, _, Crypto } from './lib/cat.js';

let siteKey = '';
let siteType = 0;

// ===== 站点常量 =====
const HOST = 'https://www.9hanju.com';

// AES 解密密钥（提取自站点 /images/home.js 中的 const newhan）
const AES_KEY = 'my-to-newhan-2025';

// 站点分类（固定写死，与站点导航一致）
const CLASSES = [
    { type_id: '1', type_name: '韩剧' },
    { type_id: '3', type_name: '韩国电影' },
    { type_id: '4', type_name: '韩国综艺' },
];

// 手机 UA —— 实测该 UA 可直连，无需 cookie
const MOBILE_UA = 'Mozilla/5.0 (X11; U; Linux x86_64; en-gb) AppleWebKit/534.35 (KHTML, like Gecko) Chrome/11.0.696.65 Safari/534.35 Puffin/2.9174AP';

/**
 * 统一请求封装
 * @param {string} reqUrl 请求地址
 * @param {object} opt    可选：{ method, body, cookie }
 */
async function request(reqUrl, opt) {
    opt = opt || {};
    const headers = {
        'User-Agent': MOBILE_UA,
        'Referer': HOST + '/',
    };
    if (opt.cookie) headers['Cookie'] = opt.cookie;
    if (opt.body) headers['Content-Type'] = 'application/x-www-form-urlencoded';

    const res = await req(reqUrl, {
        method: opt.method || 'get',
        headers: headers,
        body: opt.body,
    });
    return res.content;
}

// ===== AES-CBC 解密 =====
/**
 * 还原站点 home.js 的 aesDecrypt：
 *   1. Base64 解码 → 前 16 字节是 IV，剩余是密文
 *   2. key 取前 32 字符（UTF-8），不足 32 字节补 \0
 *   3. AES-CBC 解密 + 去 PKCS7 填充
 *
 * ⚠️ 两个关键修正（v3）：
 *   1. 不再使用 _.base64Decode —— `_` 是 lodash，没有这个方法！
 *      改用 Crypto.enc.Base64.parse()，这是 crypto-js 的标准能力。
 *   2. Crypto 来自 cat.js 的命名导出（文档：Crypto → crypto-js），
 *      之前误写成全局 CryptoJS，会直接抛 ReferenceError。
 */
function aesDecrypt(encryptedText, key) {
    // 1. Base64 解码得到原始字节（WordArray）
    const raw = Crypto.enc.Base64.parse(String(encryptedText).trim());
    const total = raw.sigBytes;

    // 2. 从 WordArray 里按字节拆出 IV（前16字节）与密文（其余）
    const ivWords = [];
    const ctWords = [];
    for (let i = 0; i < total; i++) {
        const wi = i >>> 2;
        const shift = 24 - (i % 4) * 8;
        const byte = (raw.words[wi] >>> shift) & 0xff;

        if (i < 16) {
            ivWords[wi] = (ivWords[wi] || 0) | (byte << shift);
        } else {
            const j = i - 16;
            const wj = j >>> 2;
            const shift2 = 24 - (j % 4) * 8;
            ctWords[wj] = (ctWords[wj] || 0) | (byte << shift2);
        }
    }

    // 3. 密钥处理：取前 32 个字符的 UTF-8 字节，不足则补 \0 到 32 字节
    //    注意站点用的是 key.slice(0,32).padEnd(32,'\0')，
    //    JS 的 padEnd 按「字符」补齐，但 AES 需要「字节」，所以这里手工做 UTF-8 编码。
    const keyBytes = [];
    for (let i = 0; i < key.length && keyBytes.length < 32; i++) {
        const c = key.charCodeAt(i);
        if (c < 0x80) {
            keyBytes.push(c);
        } else if (c < 0x800) {
            keyBytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
        } else {
            keyBytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
        }
    }
    while (keyBytes.length < 32) keyBytes.push(0);

    // 4. 组装 WordArray
    const keyWords = [];
    for (let i = 0; i < 32; i++) {
        const wi = i >>> 2;
        keyWords[wi] = (keyWords[wi] || 0) | (keyBytes[i] << (24 - (i % 4) * 8));
    }

    const iv = Crypto.lib.WordArray.create(ivWords, 16);
    const cipher = Crypto.lib.WordArray.create(ctWords, total - 16);
    const keyWA = Crypto.lib.WordArray.create(keyWords, 32);

    // 5. AES-CBC 解密（crypto-js 默认按 PKCS7 去填充）
    const decrypted = Crypto.AES.decrypt({ ciphertext: cipher }, keyWA, {
        iv: iv,
        mode: Crypto.mode.CBC,
        padding: Crypto.pad.Pkcs7,
    });
    return decrypted.toString(Crypto.enc.Utf8);
}

// ===== HTML 解析辅助 =====

/** 把站点的懒加载图片地址还原成真实地址 */
function fixPic(raw) {
    if (!raw) return '';
    // 形如：https://gimg1.baidu.com/gimg/app=2028&src=pics.9hanju.com/pics/3741.jpg
    const idx = raw.indexOf('src=');
    if (idx >= 0) {
        let p = raw.substring(idx + 4);
        const amp = p.indexOf('&');
        if (amp >= 0) p = p.substring(0, amp);
        if (p.indexOf('//') !== 0 && p.indexOf('http') !== 0) p = 'https://' + p;
        return p;
    }
    return raw;
}

/** 去掉字符串首尾空白和 html 标签 */
function clean(s) {
    if (!s) return '';
    return s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').trim();
}

/**
 * 解析列表页 / 首页的影片卡片
 * 结构：
 *   <li>
 *     <a class="tu lazyload" title="片名" href="/detail/ID.html" data-original="封面">
 *       <span class="play"></span><span class="bg"></span><span class="tip">状态</span></a>
 *     <p><a href="/detail/ID.html">片名</a></p><p>主演</p>
 *   </li>
 *
 * 说明：在 <a ...> 与 <span class="tip"> 之间还有 play / bg 两个 span，
 *      所以要用 [\s\S]*? 宽松跨过，不能假设 tip 紧跟其后。
 */
function parseList(html) {
    const list = [];
    const re = new RegExp(
        '<a[^>]*?title="([^"]*)"\\s+href="(/detail/\\d+\\.html)"[^>]*?data-original="([^"]*)"[^>]*?>' +
        '[\\s\\S]*?<span class="tip">([^<]*)</span>',
        'g'
    );
    let m;
    while ((m = re.exec(html)) !== null) {
        list.push({
            vod_id: m[2],
            vod_name: clean(m[1]),
            vod_pic: fixPic(m[3]),
            vod_remarks: clean(m[4]),
        });
    }
    // 去重（同一影片可能在页面多处出现）
    const seen = {};
    return list.filter(function (it) {
        if (seen[it.vod_id]) return false;
        seen[it.vod_id] = 1;
        return true;
    });
}

// ===== 必须实现的方法 =====

async function init(cfg) {
    siteKey = cfg.skey;
    siteType = cfg.stype;
}

async function home(filter) {
    const html = await request(HOST + '/');
    const list = parseList(html);
    return JSON.stringify({
        class: CLASSES,
        list: list,
    });
}

async function homeVod() {
    const html = await request(HOST + '/');
    return JSON.stringify({ list: parseList(html) });
}

/**
 * 分类列表
 * @param {string} tid    分类ID（1韩剧 / 3韩国电影 / 4韩国综艺）
 * @param {string} pg     页码，从 1 开始
 * 站点 URL 规则：/list/{tid}---{页码}.html，第 1 页页码段留空
 */
async function category(tid, pg, filter, extend) {
    pg = parseInt(pg) || 1;
    const pageSeg = pg <= 1 ? '' : String(pg - 1);
    const url = HOST + '/list/' + tid + '---' + pageSeg + '.html';
    const html = await request(url);

    return JSON.stringify({
        page: pg,
        pagecount: 9999,   // 站点只露出近 10 页，这里给大值让 App 持续翻页
        limit: 20,
        total: 9999,
        list: parseList(html),
    });
}

/**
 * 详情
 * @param {string} id 形如 "/detail/3113.html"
 */
async function detail(id) {
    if (!id) return JSON.stringify({ list: [] });

    // 兼容传纯数字 ID 的情况
    let path = id;
    if (!/^https?:\/\//.test(path) && path.indexOf('/') !== 0) {
        path = '/detail/' + path + '.html';
    }
    const url = path.indexOf('http') === 0 ? path : HOST + path;
    const html = await request(url);

    // 从路径提取剧集 ID
    const idMatch = url.match(/\/detail\/(\d+)\.html/);
    const vodId = idMatch ? idMatch[1] : '';

    // --- 基本信息 ---
    const nameM = html.match(/<dd id="m">([^<]*)<\/dd>/);
    const vodName = clean(nameM ? nameM[1] : '');

    // 通用字段：<dt>标签：</dt><dd>值</dd>
    function field(label) {
        const re = new RegExp('<dt>' + label + '：<\/dt>\\s*<dd>(?:<em>)?([^<]*)(?:<\/em>)?<\/dd>');
        const m = html.match(re);
        return m ? clean(m[1]) : '';
    }

    const vodActor = field('主演');
    const vodDirector = field('导演');
    const vodArea = field('地区') || field('电视');
    const vodRemarks = field('状态');
    const vodYear = (field('上映') || '').substring(0, 4);

    // 封面
    let vodPic = '';
    const picM = html.match(/<img class="lazyload"[^>]*?data-original="([^"]*)"/);
    if (picM) vodPic = fixPic(picM[1]);
    if (!vodPic && vodId) vodPic = 'https://pics.9hanju.com/pic/' + vodId + '.jpg';

    // 简介
    let vodContent = '';
    const cM = html.match(/<div class="juqing">([\s\S]*?)<\/div>/);
    if (cM) vodContent = clean(cM[1]);

    // --- 剧集：onclick="bb_a('3113_1_1','第01集',event)" ---
    const eps = [];
    const epRe = /bb_a\('(\d+_\d+_\d+)'\s*,\s*'([^']*)'/g;
    let em;
    while ((em = epRe.exec(html)) !== null) {
        eps.push({ uid: em[1], name: clean(em[2]) });
    }

    // 按线路分组（uid 格式：剧ID_线路_集数）
    const lines = {};
    eps.forEach(function (e) {
        const parts = e.uid.split('_');
        const lineNo = parts[1] || '1';
        if (!lines[lineNo]) lines[lineNo] = [];
        lines[lineNo].push(e);
    });

    const lineNos = Object.keys(lines).sort();
    const playFrom = [];
    const playUrl = [];
    lineNos.forEach(function (no, idx) {
        playFrom.push('线路' + (idx + 1));
        playUrl.push(
            lines[no]
                .map(function (e) {
                    return e.name + '$' + e.uid;
                })
                .join('#')
        );
    });

    if (playFrom.length === 0) {
        playFrom.push('无播放源');
        playUrl.push('');
    }

    return JSON.stringify({
        list: [
            {
                vod_id: id,
                vod_name: vodName,
                vod_pic: vodPic,
                vod_year: vodYear,
                vod_area: vodArea,
                vod_remarks: vodRemarks,
                vod_actor: vodActor,
                vod_director: vodDirector,
                vod_content: vodContent,
                vod_play_from: playFrom.join('$$$'),
                vod_play_url: playUrl.join('$$$'),
            },
        ],
    });
}

/**
 * 播放解析
 * @param {string} flag 线路名 / 或集名（不同版本 TVBox 传入不同）
 * @param {string} id   剧集 uid（本应是 "3749_1_1" 这种）
 * @param {string} flags 扩展参数
 *
 * ⚠️ 重要说明：
 * vod_play_url 的格式是「集名$剧集uid」，例如：
 *     第01集$3749_1_1
 * App 会按 $ 拆成两段，分别传给 play 的两个参数。
 * 但不同 TVBox / FreeBox 版本传参顺序不一致，可能出现：
 *     play(flag='第01集', id='3749_1_1')   ← 正常
 *     play(flag='3749_1_1', id='第01集')   ← 反的
 *     play(flag='线路1',     id='3749_1_1') ← 第一参数是线路名
 * 所以这里**不依赖参数顺序**，而是从所有参数里挑出符合
 * 「剧集uid格式」的那个（纯数字_数字_数字）。
 */
function pickUid() {
    // 剧集 uid 格式：数字_数字_数字，如 3749_1_1
    const UID_RE = /^\d+_\d+_\d+$/;

    const args = [];
    for (let i = 0; i < arguments.length; i++) {
        const v = arguments[i];
        if (v === null || v === undefined) continue;
        args.push(String(v).trim());
    }

    // 优先找严格符合 uid 格式的
    for (let i = 0; i < args.length; i++) {
        if (UID_RE.test(args[i])) return args[i];
    }

    // 退路：从形如 "第01集$3749_1_1" 的字符串里抽出 uid
    for (let i = 0; i < args.length; i++) {
        const m = args[i].match(/(\d+_\d+_\d+)/);
        if (m) return m[1];
    }

    // 再退一步：如果参数本身就是完整 URL，直接返回（说明已经是直链）
    for (let i = 0; i < args.length; i++) {
        if (/^https?:\/\//.test(args[i])) return args[i];
    }

    return args.length ? args[0] : '';
}

async function play(flag, id, flags) {
    try {
        const uid = pickUid(flag, id, flags);

        // 诊断日志：真机上出问题时，看这里能定位是哪一步断了
        console.log('[9hanju][play] 传入参数 flag=' + flag + ' id=' + id + ' -> 解析出的uid=' + uid);

        // 如果拿到的已经是直链（.m3u8 / .mp4），直接返回
        if (/^https?:\/\//.test(uid)) {
            return JSON.stringify({
                parse: 0,
                jx: 0,
                url: uid,
                header: { 'User-Agent': MOBILE_UA },
            });
        }

        // 否则走解密接口
        const enc = await request(HOST + '/u/u1.php?ud=' + uid);
        let realUrl = aesDecrypt(enc, AES_KEY);

        // 解密结果必须以 http 开头才算成功
        if (!realUrl || realUrl.indexOf('http') !== 0) {
            // 解密失败，兜底返回原值
            realUrl = uid;
        }

        console.log('[9hanju][play] 解密结果: ' + realUrl);

        return JSON.stringify({
            parse: 0,   // 直链，直接播
            jx: 0,
            url: realUrl,
            header: { 'User-Agent': MOBILE_UA },
        });
    } catch (e) {
        // 出错时兜底：把 uid 当地址返回，至少不会白屏
        let fallback = '';
        try {
            fallback = pickUid(flag, id, flags);
        } catch (e2) {
            fallback = '';
        }
        return JSON.stringify({ parse: 0, jx: 0, url: fallback });
    }
}

/**
 * 搜索
 * 站点要求 POST，且会 302 跳到相对路径 code.php?id=xxx，需要保持会话并跟随
 * 站点有搜索频率限制，被限流时返回空 —— 这里做一次延迟重试
 */
function sleep(ms) {
    return new Promise(function (r) {
        setTimeout(r, ms);
    });
}

/** 执行一次搜索请求，返回结果 HTML（失败返回空串） */
async function searchOnce(wd) {
    // 1. 先访问首页建立会话（拿 cookie）
    let cookie = '';
    try {
        const homeRes = await req(HOST + '/', {
            method: 'get',
            headers: { 'User-Agent': MOBILE_UA, 'Referer': HOST + '/' },
        });
        cookie = homeRes.cookie || '';
    } catch (e) {
        cookie = '';
    }

    // 2. POST 搜索
    const body = 'show=searchkey&keyboard=' + encodeURIComponent(wd);
    const res = await req(HOST + '/search/', {
        method: 'post',
        headers: {
            'User-Agent': MOBILE_UA,
            'Referer': HOST + '/',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookie,
        },
        body: body,
    });

    let html = res.content || '';
    const loc = res.headers && res.headers.location;
    if (loc && (!html || html.length < 500)) {
        let next;
        if (loc.indexOf('http') === 0) {
            next = loc;
        } else if (loc.charAt(0) === '/') {
            next = HOST + loc;
        } else {
            next = HOST + '/search/' + loc;
        }
        html = await request(next, { cookie: res.cookie || cookie });
    }
    return html || '';
}

/** 解析搜索结果页（结构与列表页不同） */
function parseSearch(html) {
    const list = [];
    const re = /<i>\d+\.<\/i>\s*<p id="name">\s*<a href="(\/detail\/\d+\.html)"\s+title="([^"]*)">([^<]*)<\/a>/g;
    let m;
    while ((m = re.exec(html)) !== null) {
        list.push({
            vod_id: m[1],
            vod_name: clean(m[2]),
            vod_pic: '',
            vod_remarks: '',
        });
    }
    return list;
}

async function search(wd, quick, pg) {
    const empty = JSON.stringify({ page: 1, pagecount: 0, limit: 0, total: 0, list: [] });
    try {
        let list = parseSearch(await searchOnce(wd));

        // 被限流时重试两次
        for (let i = 0; i < 2 && list.length === 0; i++) {
            await sleep(1500 + i * 1500);
            list = parseSearch(await searchOnce(wd));
        }

        if (list.length === 0) return empty;

        return JSON.stringify({
            page: 1,
            pagecount: 1,
            limit: list.length,
            total: list.length,
            list: list,
        });
    } catch (e) {
        return empty;
    }
}

// ===== 可选方法 =====

async function live(url) {
    return JSON.stringify({ url: url });
}

async function sniffer() {
    return false;
}

async function isVideo(url) {
    return url.indexOf('.mp4') >= 0 || url.indexOf('.m3u8') >= 0;
}

export function __jsEvalReturn() {
    return {
        init: init,
        home: home,
        homeVod: homeVod,
        category: category,
        detail: detail,
        play: play,
        search: search,
        live: live,
        sniffer: sniffer,
        isVideo: isVideo,
    };
}
