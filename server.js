require('dotenv').config();
const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'idex_secure_jwt_secret_key_2026';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*';

app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));
app.use(bodyParser.json({ limit: '10mb' }));

const resend = new Resend(process.env.RESEND_API_KEY);

// --- 内存数据库与状态存储 ---
const usersDb = {};         // { username: { passwordHash, fundingBalance, tradingBalance, contact, kyc, status } }
const verificationCodes = {}; 
const riskControls = {};    
const financeSubmissions = []; // 充提币申请列表
const kycSubmissions = {};  
const chatSessions = {};    // 聊天记录
const clientStates = {};    // 客户端连接及行为日志 { username: { ws, status: 'online'|'offline', lastAction: '...' } }
const clients = {};         // WebSocket 映射

// --- WebSocket 实时双向通信 ---
wss.on('connection', (ws) => {
    let clientKey = null;

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            if (data.type === 'auth') {
                clientKey = data.role === 'admin' ? 'admin' : (data.username || 'Guest');
                clients[clientKey] = { ws, role: data.role, username: data.username };
                
                if (data.role !== 'admin' && data.username) {
                    clientStates[data.username] = { status: 'online', lastAction: '登录系统', time: new Date().toLocaleTimeString() };
                    broadcastAdminSync();
                }

                if (data.role === 'admin') {
                    ws.send(JSON.stringify({ 
                        type: 'init_sync', 
                        usersDb,
                        clientStates,
                        chatSessions, 
                        financeSubmissions, 
                        kycSubmissions 
                    }));
                }
            } 
            else if (data.type === 'user_action') {
                // 记录用户行为（建仓、平仓等）
                const { username, action, pnl } = data;
                if (clientStates[username]) {
                    clientStates[username].lastAction = `${action} ${pnl !== undefined ? '(盈亏: ' + pnl + ')' : ''}`;
                    broadcastAdminSync();
                }
            }
            else if (data.type === 'chat_message') {
                const { sender, receiver, text } = data;
                if (!text) return;
                const timestamp = new Date().toLocaleTimeString();
                const targetKey = (receiver === 'admin' || !receiver) ? sender : receiver;

                if (!chatSessions[targetKey]) chatSessions[targetKey] = [];
                const msgObj = { sender, message: text, time: timestamp };
                chatSessions[targetKey].push(msgObj);

                if (clients['admin'] && clients['admin'].ws.readyState === ws.OPEN) {
                    clients['admin'].ws.send(JSON.stringify({
                        type: 'new_message',
                        chatUser: targetKey,
                        message: msgObj
                    }));
                }
                if (clients[sender] && clients[sender].ws.readyState === ws.OPEN) {
                    clients[sender].ws.send(JSON.stringify({
                        type: 'new_message',
                        chatUser: targetKey,
                        message: msgObj
                    }));
                }
            }
        } catch (e) {
            console.error('WS 解析错误:', e);
        }
    });

    ws.on('close', () => {
        if (clientKey && clientKey !== 'admin') {
            if (clientStates[clientKey]) clientStates[clientKey].status = 'offline';
            broadcastAdminSync();
            delete clients[clientKey];
        }
    });
});

function broadcastAdminSync() {
    if (clients['admin'] && clients['admin'].ws.readyState === ws.OPEN) {
        clients['admin'].ws.send(JSON.stringify({
            type: 'sync_status',
            usersDb,
            clientStates,
            financeSubmissions
        }));
    }
}

// --- RESTful API 接口 ---

// 1. 发送验证码
app.post('/api/send-code', async (req, res) => {
    const { email } = req.body;
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes[email] = code;
    try {
        await resend.emails.send({
            from: 'Web3 IDEX <support@crypto-exchange.autos>',
            to: [email],
            subject: '【Web3 IDEX】安全验证码',
            html: `<h2 style="color: #4F46E5;">验证码: ${code}</h2>`
        });
        res.json({ success: true, message: '验证码已发送' });
    } catch (e) {
        console.log(`[开发兜底] 验证码: ${code}`);
        res.json({ success: true, message: '验证码已生成' });
    }
});

// 2. 注册 (初始资金为 0)
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, contact, code } = req.body;
        if (!verificationCodes[contact] || verificationCodes[contact] !== code) {
            return res.status(400).json({ success: false, message: '验证码错误或失效' });
        }
        if (usersDb[username]) return res.status(400).json({ success: false, message: '用户已存在' });

        delete verificationCodes[contact];
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        usersDb[username] = {
            username,
            passwordHash,
            contact,
            fundingBalance: 0,   // 资金账户初始为 0
            tradingBalance: 0,   // 交易账户初始为 0
            kyc: { status: '未认证' },
            createdAt: new Date().toLocaleString()
        };
        clientStates[username] = { status: 'offline', lastAction: '注册账户' };
        broadcastAdminSync();

        res.json({ success: true, message: '注册成功' });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 3. 登录
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = usersDb[username];
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({ success: false, message: '账号或密码错误' });
        }
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, message: '登录成功', username, token, fundingBalance: user.fundingBalance, tradingBalance: user.tradingBalance });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 新增：获取用户最新双账户余额接口
app.get('/api/user/balance', (req, res) => {
    const { username } = req.query;
    const user = usersDb[username];
    if (!user) {
        return res.status(404).json({ success: false, message: '用户不存在' });
    }
    res.json({
        success: true,
        fundingBalance: user.fundingBalance,
        tradingBalance: user.tradingBalance
    });
});

// 4. 充币/提币申请提交
app.post('/api/finance/submit', (req, res) => {
    const { username, type, amount, currency, network, address, screenshot } = req.body;
    const txRecord = {
        id: 'TX' + Math.floor(100000 + Math.random() * 900000),
        username,
        type: type === 'deposit' ? '充币' : '提币',
        amount: parseFloat(amount),
        currency: currency || 'USDT',
        network: network || 'TRC20',
        address: address || '',
        screenshot: screenshot || '',
        status: '待审核',
        time: new Date().toLocaleString()
    };

    if (type === 'withdraw') {
        const user = usersDb[username];
        if (!user || (user.fundingBalance + user.tradingBalance) < parseFloat(amount)) {
            return res.status(400).json({ success: false, message: '账户余额不足' });
        }
        // 提币时先扣除资金（优先从资金账户扣除）
        user.fundingBalance = Math.max(0, user.fundingBalance - parseFloat(amount));
    }

    financeSubmissions.push(txRecord);
    broadcastAdminSync();
    res.json({ success: true, message: '申请已提交，等待管理员审核' });
});

// 5. 管理员审核充币/提币申请
app.post('/api/admin/finance/audit', (req, res) => {
    const { txId, action } = req.body; // action: 'approve' | 'reject'
    const record = financeSubmissions.find(item => item.id === txId);
    if (!record || record.status !== '待审核') {
        return res.status(404).json({ success: false, message: '记录不存在或已处理' });
    }

    const user = usersDb[record.username];
    if (action === 'approve') {
        record.status = '已通过';
        if (user && record.type === '充币') {
            user.fundingBalance += parseFloat(record.amount); // 充币到账资金账户
        }
    } else {
        record.status = '已拒绝';
        if (user && record.type === '提币') {
            user.fundingBalance += parseFloat(record.amount); // 拒绝提币则退回资金账户
        }
    }
    broadcastAdminSync();
    res.json({ success: true, message: '审核完成' });
});

// 6. 双向资金划转接口 (资金账户 ⇄ 交易账户)
app.post('/api/finance/transfer', (req, res) => {
    const { username, direction, amount } = req.body; // direction: 'fund_to_trade' | 'trade_to_fund'
    const user = usersDb[username];
    const amt = parseFloat(amount);
    if (!user || isNaN(amt) || amt <= 0) {
        return res.status(400).json({ success: false, message: '参数无效' });
    }

    if (direction === 'fund_to_trade') {
        if (user.fundingBalance < amt) return res.status(400).json({ success: false, message: '资金账户余额不足' });
        user.fundingBalance -= amt;
        user.tradingBalance += amt;
    } else {
        if (user.tradingBalance < amt) return res.status(400).json({ success: false, message: '交易账户余额不足' });
        user.tradingBalance -= amt;
        user.fundingBalance += amt;
    }

    broadcastAdminSync();
    res.json({ success: true, message: '划转成功', fundingBalance: user.fundingBalance, tradingBalance: user.tradingBalance });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Web3 IDEX 生产级后端已启动，端口: ${PORT}`);
});