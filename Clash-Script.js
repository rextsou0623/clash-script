// Clash Verge Rev / Mihomo 全局扩展脚本
// 完整替换原脚本；保留输入 DNS / TUN，重新构建规则和策略组。
// 需要支持 empty-fallback 的 Mihomo；空地区组拒绝连接，不回退到直连。
// 美国组为手动选择，应用后请在面板选择一个美国节点。
// 节点地区依据名称识别，并非实际出口地理位置检测。
// 与最新版 YAML 对齐：32 个策略组，保留手动选择、延迟选优、地区选择。
// 沿用输入节点和代理集合，不添加机场名或节点前缀，不内置机场订阅。
// HTTP 代理集合仅手动更新；规则集仍每天更新，节点健康检查仍为 360 秒。
// 客户端“订阅”页面的自动更新需在客户端设置中关闭，脚本不能修改该调度。
// ===== 全局脚本开关 =====
const SCRIPT_ENABLED = true;
// true  = 启用本脚本
// false = 完全关闭，直接使用订阅原始配置

const TEST_URL = "https://www.gstatic.com/generate_204";
const TEST_INTERVAL = 360;
const TEST_TOLERANCE = 150;

// 保留原脚本排除部分国家的意图；设为 false 可保留这些地区。
const EXCLUDE_COUNTRIES = true;
// 排除名称末尾带 [Premium] 的节点，不区分大小写。
const PREMIUM_PATTERN = "\\[premium\\]\\s*$";
// 排除纯流量统计名称，如 36.03 G | 500.00 G；流量数字变化仍有效。
const TRAFFIC_PATTERN = "^\\s*(?:\\[[^\\]\\r\\n]+\\]\\s*)?[0-9]+(?:\\.[0-9]+)?\\s*[KMGT](?:I?B)?\\s*[|｜]\\s*[0-9]+(?:\\.[0-9]+)?\\s*[KMGT](?:I?B)?\\s*$";
const INFO_PATTERN = "官网|官方|公告|订阅|链接|网站|客服|剩余|到期|流量|重置|套餐时间|(^|[^a-z])(telegram|group|channel|notice|expire|expired|traffic|reset)([^a-z]|$)";
const COUNTRY_PATTERN = "阿联酋|阿根廷|保加利亚|巴西|瑞士|智利|印度尼西亚|印度|爱尔兰|匈牙利|俄罗斯|瑞典|土耳其|荷兰|英国|法国|德国|(^|[^a-z])(arab|uae|argentina|austria|bulgaria|brazil|switzerland|chile|india|indonesia|ireland|hungary|russia|sweden|turkey|netherlands?|united[ _-]*kingdom|uk|france|germany)([^a-z]|$)";

const customRules = [
  "DOMAIN,smtp.gmail.com,DIRECT",
  "DOMAIN,hw.icoremail.net,节点选择",
  "DOMAIN-SUFFIX,cykjprint.com,DIRECT",
  "DOMAIN-SUFFIX,cnqyexp.com,DIRECT",
  "DOMAIN-SUFFIX,bisekcycle.com,🇺🇸 美国 📶",
  "DOMAIN-SUFFIX,linkseride.com,🇺🇸 美国 📶",
  "DOMAIN-SUFFIX,cyclesages.com,🇺🇸 美国 📶",
  "DOMAIN-KEYWORD,zouyang,DIRECT",
  "DOMAIN-SUFFIX,quickconnect.cn,DIRECT",
  "DOMAIN-SUFFIX,quickconnect.to,DIRECT",
  "DOMAIN-SUFFIX,synology.com,DIRECT",
  "DOMAIN-SUFFIX,synology.me,DIRECT",
  "PROCESS-NAME,SynologyDrive.exe,DIRECT"
];

const ruleProviders = {
  "ipdirect": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "ipcidr",
    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs",
    "path": "./ruleset/cncidr.mrs"
  },
  "ipprivate": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "ipcidr",
    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/private.mrs",
    "path": "./ruleset/lancidr.mrs"
  },
  "direct": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs",
    "path": "./ruleset/direct.mrs"
  },
  "private": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/private.mrs",
    "path": "./ruleset/private.mrs"
  },
  "google": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/google.mrs",
    "path": "./ruleset/google.mrs"
  },
  "shopify": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/shopify.mrs",
    "path": "./ruleset/shopify.mrs"
  },
  "microsoft": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/microsoft.mrs",
    "path": "./ruleset/microsoft.mrs"
  },
  "apple": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/apple.mrs",
    "path": "./ruleset/apple.mrs"
  },
  "bing": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/bing.mrs",
    "path": "./ruleset/bing.mrs"
  },
  "github": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/github.mrs",
    "path": "./ruleset/github.mrs"
  },
  "onedrive": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/onedrive.mrs",
    "path": "./ruleset/onedrive.mrs"
  },
  "youtube": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/youtube.mrs",
    "path": "./ruleset/youtube.mrs"
  },
  "netflix_ip": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "ipcidr",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geoip/netflix.mrs",
    "path": "./ruleset/netflix-ip.mrs"
  },
  "netflix_site": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/netflix.mrs",
    "path": "./ruleset/netflix-site.mrs"
  },
  "adobe": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/adobe.mrs",
    "path": "./ruleset/adobe.mrs"
  },
  "ai": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/ai.mrs",
    "path": "./ruleset/ai.mrs"
  },
  "bilibili": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/bilibili.mrs",
    "path": "./ruleset/bilibili.mrs"
  },
  "tiktok": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/tiktok.mrs",
    "path": "./ruleset/tiktok.mrs"
  },
  "spotify": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/spotify.mrs",
    "path": "./ruleset/spotify.mrs"
  },
  "speedtest": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/speedtest.mrs",
    "path": "./ruleset/speedtest.mrs"
  },
  "games": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/games-cn.mrs",
    "path": "./ruleset/games.mrs"
  },
  "telegramcidr": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "ipcidr",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geoip/telegram.mrs",
    "path": "./ruleset/telegramcidr.mrs"
  },
  "proxy": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo-lite/geosite/proxy.mrs",
    "path": "./rulesets/loyalsoldier/proxy.mrs"
  },
  "gfw": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/gfw.mrs",
    "path": "./ruleset/gfw.mrs"
  },
  "tld-not-cn": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/tld-!cn.mrs",
    "path": "./ruleset/tld-not-cn.mrs"
  },
  "telegram": {
    "type": "http",
    "format": "mrs",
    "interval": 86400,
    "behavior": "domain",
    "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/telegram.mrs",
    "path": "./ruleset/telegram.mrs"
  }
};

const proxyGroups = [
  {
    "hidden": false,
    "disable-udp": false,
    "name": "节点选择",
    "type": "select",
    "proxies": [
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "手动选择",
    "type": "select",
    "include-all": true,
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "漏网之鱼",
    "type": "select",
    "proxies": [
      "节点选择",
      "全局直连",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Bing",
    "type": "select",
    "proxies": [
      "节点选择",
      "全局直连",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://www.bing.com/favicon.ico"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Github",
    "type": "select",
    "proxies": [
      "节点选择",
      "手动选择",
      "全局直连",
      "延迟选优"
    ],
    "icon": "https://www.clashverge.dev/assets/icons/github.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "谷歌服务",
    "type": "select",
    "proxies": [
      "节点选择",
      "手动选择",
      "全局直连",
      "延迟选优"
    ],
    "icon": "https://www.clashverge.dev/assets/icons/google.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Shopify",
    "type": "select",
    "proxies": [
      "节点选择",
      "手动选择",
      "全局直连",
      "延迟选优"
    ],
    "icon": "https://www.shopify.com/favicon.ico"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "苹果服务",
    "type": "select",
    "proxies": [
      "全局直连",
      "节点选择",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://www.clashverge.dev/assets/icons/apple.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "微软服务",
    "type": "select",
    "proxies": [
      "全局直连",
      "节点选择",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/microsoft.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Onedrive",
    "type": "select",
    "proxies": [
      "节点选择",
      "全局直连",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/OneDrive.png"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "AI",
    "type": "select",
    "proxies": [
      "🇺🇸 美国 📶",
      "手动选择",
      "节点选择"
    ],
    "icon": "https://www.clashverge.dev/assets/icons/chatgpt.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Bilibili",
    "type": "select",
    "proxies": [
      "全局直连"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/Orz-3/mini@master/Color/Bili.png"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "YouTube",
    "type": "select",
    "proxies": [
      "节点选择",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/youtube.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Netflix",
    "type": "select",
    "proxies": [
      "节点选择",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://www.clashverge.dev/assets/icons/netflix.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "TikTok",
    "type": "select",
    "proxies": [
      "🇺🇸 美国 📶",
      "🇸🇬 新加坡 📶",
      "🇹🇼 台湾 📶",
      "节点选择",
      "手动选择",
    ],
    "icon": "https://fastly.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/tiktok.png"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Spotify",
    "type": "select",
    "proxies": [
      "节点选择",
      "全局直连",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Spotify.png"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "Adobe",
    "type": "select",
    "proxies": [
      "全局直连",
      "节点选择",
      "REJECT"
    ],
    "icon": "https://www.adobe.com/favicon.ico"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "游戏服务",
    "type": "select",
    "proxies": [
      "全局直连",
      "节点选择",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://www.clashverge.dev/assets/icons/steam.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "电报消息",
    "type": "select",
    "proxies": [
      "节点选择",
      "手动选择",
      "延迟选优"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "网速测试",
    "type": "select",
    "proxies": [
      "全局直连"
    ],
    "include-all": true,
    "icon": "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Speedtest.png"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "全局直连",
    "type": "select",
    "proxies": [
      "DIRECT"
    ],
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg"
  },
  {
    "hidden": false,
    "disable-udp": false,
    "name": "延迟选优",
    "type": "url-test",
    "include-all": true,
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/speed.svg"
  }
];

const regionConfig = [
  {
    "name": "🇺🇸 美国 📶",
    "matcher": "美国|🇺🇸|(^|[^a-z])(us|usa)([^a-z]|$)|united[ _-]*states|america",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg"
  },
  {
    "name": "🇯🇵 日本 📶",
    "matcher": "日本|🇯🇵|(^|[^a-z])jp([^a-z]|$)|japan",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/jp.svg"
  },
  {
    "name": "🇰🇷 韩国 📶",
    "matcher": "韩国|韓國|🇰🇷|(^|[^a-z])kr([^a-z]|$)|korea",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/kr.svg"
  },
  {
    "name": "🇸🇬 新加坡 📶",
    "matcher": "新加坡|🇸🇬|狮城|獅城|(^|[^a-z])sg([^a-z]|$)|singapore",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg"
  },
  {
    "name": "🇭🇰 香港 📶",
    "matcher": "香港|🇭🇰|(^|[^a-z])hk([^a-z]|$)|hong[ _-]*kong",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg"
  },
  {
    "name": "🇹🇼 台湾 📶",
    "matcher": "台湾|台灣|🇹🇼|(^|[^a-z])tw([^a-z]|$)|tai[ _-]*wan",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg"
  },
  {
    "name": "🇨🇳 中国 📶",
    "matcher": "中国|中國|大陆|大陸|🇨🇳|(^|[^a-z])cn([^a-z]|$)|china",
    "icon": "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/cn.svg"
  },
  {
    "name": "🌐 其他 📶",
    "icon": "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png"
  }
];

const snifferConfig = {
  "enable": true,
  "force-dns-mapping": false,
  "parse-pure-ip": true,
  "override-destination": false,
  "sniff": {
    "TLS": {
      "ports": [
        443,
        8443
      ]
    },
    "HTTP": {
      "ports": [
        80,
        "8080-8880"
      ],
      "override-destination": false
    },
    "QUIC": {
      "ports": [
        443,
        8443
      ]
    }
  }
};

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

function combineFilters(existing, added) {
    // Mihomo 使用单个反引号分隔正则；兼容输入中连续的反引号，避免产生匹配全部节点的空表达式。
    const parts = existing ? String(existing).split(/`+/).filter(Boolean) : [];
    if (added && !parts.includes(added)) parts.push(added);
    return parts.join("`");
}

function main(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
        throw new Error("订阅配置必须是对象");
    }

        // ===== 总开关 =====
    if (!SCRIPT_ENABLED) {
        return input;
    }
    
    // 每次创建独立对象，避免反复执行时重复追加组或改变原订阅。
    const config = clone(input);
    // smtp.gmail.com 强制使用系统 DNS
    if (!config.dns || typeof config.dns !== "object" || Array.isArray(config.dns)) {
        config.dns = {};
    }

    if (
        !config.dns["nameserver-policy"] ||
        typeof config.dns["nameserver-policy"] !== "object" ||
        Array.isArray(config.dns["nameserver-policy"])
    ) {
        config.dns["nameserver-policy"] = {};
    }

    config.dns["nameserver-policy"]["smtp.gmail.com"] = [
      "223.5.5.5",
      "223.6.6.6"
    ];
    config.dns["direct-nameserver-follow-policy"] = true;
    const pattern = INFO_PATTERN + "|" + TRAFFIC_PATTERN + "|" + PREMIUM_PATTERN + (EXCLUDE_COUNTRIES ? "|" + COUNTRY_PATTERN : "");
    const excludeReg = new RegExp(pattern, "i");
    const goExclude = "(?i)(?:" + pattern + ")";
    if (config.proxies !== undefined && !Array.isArray(config.proxies)) {
        throw new Error("proxies 必须是数组");
    }
    config.proxies = (config.proxies || []).filter(p => p && typeof p.name === "string" && p.name && !excludeReg.test(p.name));
    const providers = config["proxy-providers"] || {};
    if (typeof providers !== "object" || Array.isArray(providers)) {
        throw new Error("proxy-providers 必须是对象");
    }
    for (const [name, provider] of Object.entries(providers)) {
        if (!provider || typeof provider !== "object") throw new Error("无效订阅提供商：" + name);
        // 仅关闭节点集合的定时下载；健康检查仍保持每 360 秒。
        if (provider.type === "http") provider.interval = 0;
        provider["exclude-filter"] = combineFilters(provider["exclude-filter"], goExclude);
        // 提供商节点由提供商健康检查负责；保留其已有 URL 和其他参数。
        provider["health-check"] = {
            enable: true, url: TEST_URL, interval: TEST_INTERVAL, timeout: 5000, lazy: true,
            ...(provider["health-check"] || {}), enable: true
        };
        if (!(provider["health-check"].interval > 0)) provider["health-check"].interval = TEST_INTERVAL;
    }
    if (config.proxies.length === 0 && Object.keys(providers).length === 0) {
        throw new Error("过滤后没有可用节点或订阅提供商，请检查订阅和过滤条件");
    }

    config.profile = {...(config.profile || {}), "store-selected": true};
    // 仅为 smtp.gmail.com 增加系统 DNS 策略；其余 DNS、TUN、浏览器指纹和 User-Agent 保持原样。
    config["unified-delay"] = true;
    config["tcp-concurrent"] = true;
    // 有原嗅探配置则原样保留（包括 enable:false）。
    if (config.sniffer === undefined) config.sniffer = clone(snifferConfig);

    const groups = clone(proxyGroups);
    const regionNames = regionConfig.map(r => r.name);
    const allRegions = regionConfig.filter(r => r.matcher).map(r => "(?:" + r.matcher + ")").join("|");
    const health = {url: TEST_URL, interval: TEST_INTERVAL, timeout: 5000, lazy: true};
    for (const group of groups) {
        if (group.type === "url-test") Object.assign(group, health);
        if (group.type === "url-test") group.tolerance = TEST_TOLERANCE;
        if (group["include-all"]) {
            group["exclude-filter"] = goExclude;
            group["empty-fallback"] = "REJECT";
        }
        if (group.name === "节点选择") group.proxies.splice(2, 0, "地区选择");
        else if (group.type === "select" && group.proxies && !group["include-all"] && !["全局直连", "Bilibili"].includes(group.name)) {
            group.proxies = [...new Set([...group.proxies, ...regionNames])];
        }
    }
    groups.splice(1, 0, {name: "地区选择", type: "select", proxies: regionNames});
    for (const region of regionConfig) {
        const manual = region.name === "🇺🇸 美国 📶";
        const group = {
            name: region.name, type: manual ? "select" : "url-test",
            "include-all": true, "empty-fallback": "REJECT",
            "exclude-filter": goExclude, icon: region.icon
        };
        if (region.matcher) group.filter = "(?i)(?:" + region.matcher + ")";
        else group["exclude-filter"] = combineFilters(goExclude, "(?i)(?:" + allRegions + ")");
        if (!manual) Object.assign(group, health, {tolerance: TEST_TOLERANCE});
        groups.push(group);
    }
    config["proxy-groups"] = groups;
    config["rule-providers"] = clone(ruleProviders);
    // 专用域名规则先于宽泛的国内/国外规则；IP 规则作为后续兜底。
    config.rules = [
        "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
        ...customRules,
        "RULE-SET,private,全局直连",
        "RULE-SET,ipprivate,全局直连,no-resolve",
        "RULE-SET,ai,AI",
        "RULE-SET,youtube,YouTube",
        "RULE-SET,bing,Bing",
        "RULE-SET,github,Github",
        "RULE-SET,shopify,Shopify",
        "RULE-SET,onedrive,Onedrive",
        "RULE-SET,telegram,电报消息",
        "RULE-SET,apple,苹果服务",
        "RULE-SET,google,谷歌服务",
        "RULE-SET,microsoft,微软服务",
        "RULE-SET,netflix_site,Netflix",
        "RULE-SET,tiktok,TikTok",
        "RULE-SET,adobe,Adobe",
        "RULE-SET,spotify,Spotify",
        "RULE-SET,games,游戏服务",
        "RULE-SET,speedtest,网速测试",
        "RULE-SET,bilibili,Bilibili",
        "RULE-SET,direct,全局直连",
        "RULE-SET,telegramcidr,电报消息,no-resolve",
        "RULE-SET,netflix_ip,Netflix,no-resolve",
        "RULE-SET,proxy,节点选择",
        "RULE-SET,gfw,节点选择",
        "RULE-SET,tld-not-cn,节点选择",
        // 对仍未匹配的域名允许解析，以覆盖规则集未收录的国内网站。
        "RULE-SET,ipdirect,全局直连",
        "MATCH,漏网之鱼"
    ];

    // 检查固定名称冲突及原订阅中依赖已被替换策略组的连接链。
    const names = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]);
    for (const item of [...config.proxies, ...groups]) {
        if (names.has(item.name)) throw new Error("节点或策略组名称重复：" + item.name);
        names.add(item.name);
    }
    for (const group of groups) for (const name of group.proxies || []) {
        if (!names.has(name)) throw new Error("策略组引用不存在：" + name);
    }
    for (const item of [...config.proxies, ...Object.values(providers)]) {
        const dependency = item["dialer-proxy"] || item.proxy;
        if (dependency && !names.has(dependency)) throw new Error("原订阅依赖的代理已不存在：" + dependency + "；请调整 dialer-proxy / provider.proxy");
    }
    return config;
}
