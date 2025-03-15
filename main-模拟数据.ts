import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// 添加登录尝试记录存储
const loginAttempts = new Map<string, { count: number; timestamp: number }>();

// 配置
const CONFIG = {
  system: {
    password: 'admin123456',
    tokenSecret: 'FuckCracker123',
    tokenExpiry: 24 * 60 * 60 * 1000, // 24小时
    maxLoginAttempts: 3,               // 最大登录尝试次数
    loginLockTime: 60 * 60 * 1000,    // 锁定时间（1小时）
  },
  pageSize: 10
};

// 模拟数据
const MOCK_DATA = [
  {
    product_name: "Router-A100",
    username: "admin",
    password: "admin123",
    protocol: "HTTP",
    user_role: "管理员",
    created_at: "2024-01-01"
  },
  {
    product_name: "Switch-B200",
    username: "root",
    password: "root123",
    protocol: "HTTPS",
    user_role: "超级管理员",
    created_at: "2024-01-02"
  },
  {
    product_name: "Camera-C300",
    username: "user",
    password: "user123",
    protocol: "RTSP",
    user_role: "普通用户",
    created_at: "2024-01-03"
  },
  {
    product_name: "NVR-D400",
    username: "admin",
    password: "12345678",
    protocol: "RTSP",
    user_role: "管理员",
    created_at: "2024-01-04"
  },
  {
    product_name: "Gateway-E500",
    username: "system",
    password: "sys123",
    protocol: "HTTP",
    user_role: "系统管理员",
    created_at: "2024-01-05"
  },
  {
    product_name: "Firewall-F600",
    username: "admin",
    password: "firewall123",
    protocol: "HTTPS",
    user_role: "安全管理员",
    created_at: "2024-01-06"
  },
  {
    product_name: "DVR-G700",
    username: "operator",
    password: "dvr@123",
    protocol: "RTSP",
    user_role: "操作员",
    created_at: "2024-01-07"
  },
  {
    product_name: "AccessPoint-H800",
    username: "admin",
    password: "ap123456",
    protocol: "HTTP",
    user_role: "管理员",
    created_at: "2024-01-08"
  },
  {
    product_name: "Controller-I900",
    username: "supervisor",
    password: "super123",
    protocol: "HTTPS",
    user_role: "主管",
    created_at: "2024-01-09"
  },
  {
    product_name: "Server-J1000",
    username: "root",
    password: "server@root",
    protocol: "SSH",
    user_role: "超级管理员",
    created_at: "2024-01-10"
  },
  {
    product_name: "SmartSwitch-K100",
    username: "admin",
    password: "switch@123",
    protocol: "TELNET",
    user_role: "管理员",
    created_at: "2024-01-11"
  },
  {
    product_name: "IPCamera-L200",
    username: "viewer",
    password: "view123",
    protocol: "RTSP",
    user_role: "访客",
    created_at: "2024-01-12"
  },
  {
    product_name: "LoadBalancer-M300",
    username: "admin",
    password: "lb@admin",
    protocol: "HTTPS",
    user_role: "管理员",
    created_at: "2024-01-13"
  },
  {
    product_name: "StorageNAS-N400",
    username: "storage",
    password: "nas@123",
    protocol: "FTP",
    user_role: "存储管理员",
    created_at: "2024-01-14"
  },
  {
    product_name: "WirelessBridge-O500",
    username: "admin",
    password: "bridge123",
    protocol: "HTTP",
    user_role: "管理员",
    created_at: "2024-01-15"
  },
  {
    product_name: "SecurityGateway-P600",
    username: "security",
    password: "sec@123",
    protocol: "HTTPS",
    user_role: "安全管理员",
    created_at: "2024-01-16"
  },
  {
    product_name: "MediaServer-Q700",
    username: "media",
    password: "media@123",
    protocol: "RTMP",
    user_role: "媒体管理员",
    created_at: "2024-01-17"
  },
  {
    product_name: "NetworkMonitor-R800",
    username: "monitor",
    password: "mon@123",
    protocol: "SNMP",
    user_role: "监控员",
    created_at: "2024-01-18"
  },
  {
    product_name: "VPNGateway-S900",
    username: "vpnuser",
    password: "vpn@123",
    protocol: "PPTP",
    user_role: "VPN管理员",
    created_at: "2024-01-19"
  },
  {
    product_name: "WebProxy-T1000",
    username: "proxy",
    password: "proxy@123",
    protocol: "HTTP",
    user_role: "代理管理员",
    created_at: "2024-01-20"
  },
  {
    product_name: "DataCenter-U100",
    username: "dcadmin",
    password: "dc@123",
    protocol: "HTTPS",
    user_role: "数据中心管理员",
    created_at: "2024-01-21"
  },
  {
    product_name: "CloudServer-V200",
    username: "cloud",
    password: "cloud@123",
    protocol: "SSH",
    user_role: "云管理员",
    created_at: "2024-01-22"
  },
  {
    product_name: "BackupSystem-W300",
    username: "backup",
    password: "bak@123",
    protocol: "FTP",
    user_role: "备份管理员",
    created_at: "2024-01-23"
  }
];

// HTML 模板
const scriptContent = `
    let currentPage = 1;
    let totalSize = 0;
    let currentQuery = '';

    async function login(password) {
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const data = await response.json();
            if (data.success) {
                localStorage.setItem('token', data.token);
                return true;
            }
            return false;
        } catch (e) {
            return false;
        }
    }

    async function fetchSecurityData(query, page = 1) {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                showLoginPage();
                return null;
            }

            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': token
                },
                body: JSON.stringify({ query, page })
            });

            if (!response.ok) {
                if (response.status === 401) {
                    showLoginPage();
                    return null;
                }
                throw new Error('请求失败');
            }

            const data = await response.json();
            totalSize = data.total || 0;
            return data;
        } catch (e) {
            alert('查询出错：' + e.message);
            return null;
        }
    }

    function showMainPage() {
        document.getElementById('loginPage').classList.add('hidden');
        document.getElementById('mainPage').classList.remove('hidden');
    }

    function showLoginPage() {
        document.getElementById('loginPage').classList.remove('hidden');
        document.getElementById('mainPage').classList.add('hidden');
        localStorage.removeItem('token');
    }

    function getIconPath(color) {
        const icons = {
            // 产品名称图标 - 设备/产品图标
            blue: 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z',
            // 用户名图标 - 用户图标
            green: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
            // 密码图标 - 锁定图标
            red: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8V7a4 4 0 00-8 0v4h8z',
            // 协议图标 - 网络/连接图标
            purple: 'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4',
            // 用户角色图标 - 身份标识图标
            orange: 'M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z'
        };
        return icons[color];
    }

    function createCell(value, label, color) {
        return \`
            <div class="flex items-center gap-3">
                <div class="w-8 h-8 flex items-center justify-center rounded-lg bg-\${color}-50">
                    <svg class="w-4 h-4 text-\${color}-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="\${getIconPath(color)}"/>
                    </svg>
                </div>
                <div class="flex-1 min-w-0">
                    <div class="text-gray-800 text-sm">\${value}</div>
                    <span class="text-gray-500 text-xs">\${label}</span>
                </div>
            </div>
        \`;
    }

    function renderTable(data) {
        const tbody = document.querySelector('tbody');
        tbody.innerHTML = '';

        if (!data?.results?.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-8 text-center text-gray-500">暂无数据</td></tr>';
            return;
        }

        data.results.forEach(record => {
            const row = document.createElement('tr');
            row.className = 'table-row border-b border-gray-100';
            row.innerHTML = \`
                <td class="py-3 px-4">\${createCell(record.product_name, '产品名称', 'blue')}</td>
                <td class="py-3 px-4">\${createCell(record.username, '用户名', 'green')}</td>
                <td class="py-3 px-4">\${createCell(record.password, '密码', 'red')}</td>
                <td class="py-3 px-4">\${createCell(record.protocol, '协议', 'purple')}</td>
                <td class="py-3 px-4">\${createCell(record.user_role, '用户角色', 'orange')}</td>
            \`;
            tbody.appendChild(row);
        });

        document.getElementById('pageInfo').innerHTML = \`
            <div class="bg-indigo-50 text-indigo-600 px-2.5 py-0.5 rounded-full text-xs font-medium inline-block">
                第 \${data.page} 页，共 \${Math.ceil(data.total / ${CONFIG.pageSize})} 页
            </div>
            <div class="mt-1 text-xs text-gray-500">
                共找到 \${data.total} 条结果
            </div>
        \`;

        updatePagination();
    }

    function updatePagination() {
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');
        const totalPages = Math.ceil(totalSize / ${CONFIG.pageSize});
        
        prevBtn.disabled = currentPage <= 1;
        nextBtn.disabled = currentPage >= totalPages;
    }

    window.onload = async function() {
        const token = localStorage.getItem('token');
        if (token) {
            showMainPage();
            const data = await fetchSecurityData('', 1);
            if (data) renderTable(data);
        }

        document.getElementById('loginBtn').addEventListener('click', async () => {
            const password = document.getElementById('passwordInput').value;
            if (await login(password)) {
                showMainPage();
                const data = await fetchSecurityData('', 1);
                if (data) renderTable(data);
            } else {
                alert('密码错误，请重试！');
            }
        });

        document.getElementById('searchBtn').addEventListener('click', async () => {
            const query = document.getElementById('searchInput').value.trim();
            currentQuery = query;
            currentPage = 1;
            
            try {
                const searchBtn = document.getElementById('searchBtn');
                searchBtn.disabled = true;
                searchBtn.textContent = '查询中...';
                
                const data = await fetchSecurityData(query, 1);
                if (data) renderTable(data);
            } finally {
                const searchBtn = document.getElementById('searchBtn');
                searchBtn.disabled = false;
                searchBtn.textContent = '查询';
            }
        });

        document.getElementById('resetBtn').addEventListener('click', async () => {
            document.getElementById('searchInput').value = '';
            currentQuery = '';
            currentPage = 1;
            const data = await fetchSecurityData('', 1);
            if (data) renderTable(data);
        });

        document.getElementById('logoutBtn').addEventListener('click', () => {
            if (confirm('确定要退出登录吗？')) showLoginPage();
        });

        document.getElementById('prevBtn').addEventListener('click', async () => {
            if (currentPage > 1) {
                const data = await fetchSecurityData(currentQuery, currentPage - 1);
                if (data) {
                    currentPage--;
                    renderTable(data);
                }
            }
        });

        document.getElementById('nextBtn').addEventListener('click', async () => {
            const totalPages = Math.ceil(totalSize / ${CONFIG.pageSize});
            if (currentPage < totalPages) {
                const data = await fetchSecurityData(currentQuery, currentPage + 1);
                if (data) {
                    currentPage++;
                    renderTable(data);
                }
            }
        });
    };
`;

const htmlContent = `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>设备默认密码查询系统</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .table-row { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .table-row:hover { background-color: #f8fafc; transform: translateX(4px); }
        .gradient-bg { background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%); }
        .glass-effect { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(12px); }
    </style>
</head>
<body class="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
    <!-- 登录页面 -->
    <div id="loginPage" class="min-h-screen flex items-center justify-center p-6">
        <div class="glass-effect rounded-xl p-8 shadow-lg max-w-md w-full">
            <h2 class="text-2xl font-bold text-gray-800 mb-6 text-center">系统登录</h2>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">访问密码</label>
                    <input type="password" id="passwordInput" class="w-full px-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <button id="loginBtn" class="w-full px-6 py-2 gradient-bg text-white rounded-lg">登录</button>
            </div>
        </div>
    </div>

    <!-- 主页面 -->
    <div id="mainPage" class="hidden min-h-screen p-6">
        <div class="max-w-7xl mx-auto space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold text-gray-800">设备默认密码查询系统</h1>
                <button id="logoutBtn" class="px-4 py-2 border border-gray-200 text-gray-600 rounded-lg text-sm">退出登录</button>
            </div>

            <div class="glass-effect rounded-xl p-4 shadow-md">
                <div class="flex gap-3">
                    <input type="text" id="searchInput" class="flex-1 px-4 py-2 border border-gray-200 rounded-lg text-sm" placeholder="输入关键词搜索...">
                    <button id="searchBtn" class="px-4 py-2 gradient-bg text-white rounded-lg text-sm">查询</button>
                    <button id="resetBtn" class="px-4 py-2 border border-gray-200 text-gray-600 rounded-lg text-sm">重置</button>
                </div>
            </div>

            <div class="glass-effect rounded-xl overflow-hidden shadow-md">
                <table class="w-full">
                    <thead>
                        <tr class="bg-gray-50/80">
                            <th class="text-left py-3 px-4 text-gray-600 text-xs font-medium">产品名称</th>
                            <th class="text-left py-3 px-4 text-gray-600 text-xs font-medium">用户名</th>
                            <th class="text-left py-3 px-4 text-gray-600 text-xs font-medium">密码</th>
                            <th class="text-left py-3 px-4 text-gray-600 text-xs font-medium">协议</th>
                            <th class="text-left py-3 px-4 text-gray-600 text-xs font-medium">用户角色</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>

            <div class="flex justify-between items-center">
                <div id="pageInfo" class="text-sm text-gray-600"></div>
                <div class="flex gap-2">
                    <button id="prevBtn" class="px-3 py-1 border text-gray-600 rounded text-xs">上一页</button>
                    <button id="nextBtn" class="px-3 py-1 gradient-bg text-white rounded text-xs">下一页</button>
                </div>
            </div>
        </div>
    </div>

    <script>${scriptContent}</script>
</body>
</html>`;

// JWT 相关函数
const jwt = {
  generate: (timestamp: number): string => btoa(`${timestamp}.${CONFIG.system.tokenSecret}`),
  verify: (token: string): boolean => {
    try {
      const [timestamp, secret] = atob(token).split('.');
      return secret === CONFIG.system.tokenSecret && 
             (Date.now() - parseInt(timestamp) <= CONFIG.system.tokenExpiry);
    } catch {
      return false;
    }
  }
};

// 修改 API 处理函数,移除日志记录
const apiHandlers = {
  async login(password: string, ip: string) {
    // 检查是否被锁定
    const attempt = loginAttempts.get(ip);
    const now = Date.now();
    
    if (attempt) {
      if (attempt.count >= CONFIG.system.maxLoginAttempts) {
        const lockTimeRemaining = attempt.timestamp + CONFIG.system.loginLockTime - now;
        if (lockTimeRemaining > 0) {
          const minutesRemaining = Math.ceil(lockTimeRemaining / 60000);
          throw new Error(`登录已被锁定，请在 ${minutesRemaining} 分钟后重试`);
        } else {
          loginAttempts.delete(ip);
        }
      }
    }

    if (password === CONFIG.system.password) {
      loginAttempts.delete(ip);
      return { success: true, token: jwt.generate(Date.now()) };
    }

    const newAttempt = attempt || { count: 0, timestamp: now };
    newAttempt.count++;
    newAttempt.timestamp = now;
    loginAttempts.set(ip, newAttempt);

    const attemptsLeft = CONFIG.system.maxLoginAttempts - newAttempt.count;
    throw new Error(`密码错误，还剩 ${attemptsLeft} 次尝试机会`);
  },

  async search(query: string = '', page: number = 1, token: string) {
    if (!jwt.verify(token)) {
      throw new Error('未授权访问');
    }

    const sanitizedQuery = this.sanitizeInput(query.trim());
    const sanitizedPage = Math.max(1, Math.floor(Number(page)));

    try {
      return await this.executeSearch(sanitizedQuery, sanitizedPage);
    } catch (error) {
      throw new Error('数据查询失败');
    }
  },

  // 使用模拟数据进行搜索
  async executeSearch(query: string, page: number) {
    const filteredData = MOCK_DATA.filter(item => {
      if (!query) return true;
      const searchStr = query.toLowerCase();
      return (
        item.product_name.toLowerCase().includes(searchStr) ||
        item.username.toLowerCase().includes(searchStr) ||
        item.protocol.toLowerCase().includes(searchStr) ||
        item.user_role.toLowerCase().includes(searchStr)
      );
    });

    const total = filteredData.length;
    const startIndex = (page - 1) * CONFIG.pageSize;
    const results = filteredData.slice(startIndex, startIndex + CONFIG.pageSize);

    return { 
      results, 
      total, 
      page, 
      query, 
      pageSize: CONFIG.pageSize 
    };
  },

  // 输入净化函数
  sanitizeInput(input: string): string {
    return input.replace(/[<>]/g, ''); // 简单的XSS防护
  }
};

// 修改请求处理器
const handler = async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const clientIP = req.headers.get('x-forwarded-for') || 'unknown';
  
  try {
    if (url.pathname === '/api/login' && req.method === 'POST') {
      const { password } = await req.json();
      try {
        const result = await apiHandlers.login(password, clientIP);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ 
          success: false, 
          message: e.message 
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    if (url.pathname === '/api/search' && req.method === 'POST') {
      const { query, page } = await req.json();
      const token = req.headers.get('Authorization');
      
      try {
        const data = await apiHandlers.search(query, page, token!);
        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ 
          success: false, 
          message: e.message 
        }), {
          status: e.message === '未授权访问' ? 401 : 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    return new Response(htmlContent, {
      headers: { "content-type": "text/html" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ 
      success: false, 
      message: '请求处理失败' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

await serve(handler, { port: 8000 });