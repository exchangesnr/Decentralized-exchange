require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');

const app = express();
app.use(express.json());
app.use(cors());

// 初始化 Resend 邮件客户端
const resend = new Resend(process.env.RESEND_API_KEY);

// 临时存储验证码（生产环境建议存入 Redis）
const verificationCodes = new Map();

// 根目录测试
app.get('/', (req, res) => {
    res.send('🎉 交易所后端服务器正在正常运行中！');
});

// 1. 发送验证码接口
app.post('/api/send-code', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, message: '请输入电子邮箱' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes.set(email, { code, expires: Date.now() + 5 * 60 * 1000 });

    try {
        const data = await resend.emails.send({
            from: 'Exchange Security <noreply@crypto-exchange.autos>',
            to: [email],
            subject: '【交易所】您的注册验证码',
            html: `<p>您好，您的注册验证码为：<strong>${code}</strong>，有效时间为 5 分钟。</p>`
        });

        console.log('邮件发送成功:', data);
        res.json({ success: true, message: '验证码已发送到您的邮箱' });
    } catch (error) {
        console.error('邮件发送失败:', error);
        res.status(500).json({ success: false, message: '邮件发送失败，请检查 API Key 配置' });
    }
});

// 2. 校验验证码并完成注册接口
app.post('/api/register', (req, res) => {
    const { username, password, birthday, address, contact, code } = req.body;

    const record = verificationCodes.get(contact);
    if (!record || record.code !== code || Date.now() > record.expires) {
        return res.status(400).json({ success: false, message: '验证码错误或已过期' });
    }

    // 验证通过后清除记录
    verificationCodes.delete(contact);
    res.json({ success: true, message: '注册成功' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`后端服务器已在端口 ${PORT} 启动运行`);
});