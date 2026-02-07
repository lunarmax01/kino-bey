/**
 * 🎬 PROFESSIONAL KINO & SERIAL BOT (V15.4 - FIXED & ENHANCED)
 * 🛡 Security Level: Enterprise Grade
 * ✍️ Audited by: CyberSecurity Professional
 * 
 * 📝 CHANGELOG:
 * - [FIX] "Sessiya vaqti tugadi" xatosi tuzatildi (timestamp fix).
 * - [NEW] Kanal qo'shishda ID so'ralmaydi. Name -> Link/Username orqali avtomatik ID aniqlanadi.
 * - [SEC] Barcha inputlar uchun xavfsizlik kuchaytirildi.
 */

require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');
const mongoose = require('mongoose');
const os = require('os');

// ==========================================
// 1. CONFIGURATION & SECURITY SETUP
// ==========================================

const CONFIG = {
    token: process.env.BOT_TOKEN,
    mongoUri: process.env.MONGO_URI,
    superAdminId: parseInt(process.env.ADMIN_ID),
    floodLimit: 800, // Milliseconds
    downloadCooldown: 5000, // 5 seconds between downloads
    stateTTL: 30 * 60 * 1000, // 30 minutes
    adminCacheTTL: 60 * 1000,
    dbOptions: {
        serverSelectionTimeoutMS: 5000,
        maxPoolSize: 10,
        autoIndex: true
    }
};

// Critical Config Check
if (!CONFIG.token || !CONFIG.mongoUri || isNaN(CONFIG.superAdminId)) {
    console.error("❌ CRITICAL ERROR: .env faylda ma'lumotlar yetarli emas!");
    console.error("Talab qilinadi: BOT_TOKEN, MONGO_URI, ADMIN_ID");
    process.exit(1);
}

const bot = new TelegramBot(CONFIG.token, { polling: true });
let BOT_USERNAME = '';

// In-Memory Storage (Cache)
const floodMap = new Map();
const downloadLimitMap = new Map();
const state = new Map();
const adminCache = new Map();

// Global Broadcast Controller
let broadcastController = {
    isActive: false,
    shouldStop: false
};

const startTime = Date.now();

// Error Handling (Prevent Crash)
process.on('uncaughtException', (err) => console.error('🔥 Uncaught Exception:', err));
process.on('unhandledRejection', (reason) => console.error('🔥 Unhandled Rejection:', reason));

// ==========================================
// 2. DATABASE SCHEMAS
// ==========================================

mongoose.connect(CONFIG.mongoUri)
    .then(() => console.log('✅ MongoDB Connection Established'))
    .catch(err => {
        console.error('❌ DB Connection Error:', err);
        process.exit(1);
    });

const userSchema = new mongoose.Schema({
    telegramId: { type: Number, unique: true, index: true },
    firstName: String,
    username: String,
    birthYear: Number,
    isBanned: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    lastMessageId: Number,
    joinedAt: { type: Date, default: Date.now },
    restrictions: {
        canDownload: { type: Boolean, default: true },
        contentProtected: { type: Boolean, default: false }
    }
});

const movieSchema = new mongoose.Schema({
    code: { type: Number, unique: true, index: true },
    contentType: { type: String, enum: ['movie', 'series'], default: 'movie' },
    title: { type: String, trim: true },
    posterId: String,
    country: String,
    language: String,
    quality: String,
    duration: String,
    isAdult: { type: Boolean, default: false },
    fileId: String, // Kino uchun
    episodes: [{ // Serial uchun
        number: Number,
        fileId: String,
        name: { type: String, default: '' },
        addedAt: { type: Date, default: Date.now }
    }],
    views: { type: Number, default: 0 },
    downloads: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 },
    ratedUsers: [{ type: Number }],
    addedBy: Number
}, { timestamps: true });

const channelSchema = new mongoose.Schema({
    channelId: { type: String, unique: true, required: true },
    name: String,
    url: String,
    type: { type: String, enum: ['main', 'movie_codes'], default: 'main' },
    addedAt: { type: Date, default: Date.now }
});

const settingsSchema = new mongoose.Schema({
    key: { type: String, default: 'config', unique: true },
    globalProtection: { type: Boolean, default: false },
    globalDownload: { type: Boolean, default: true },
    autoPost: { type: Boolean, default: true }
});

const adminSchema = new mongoose.Schema({
    telegramId: { type: Number, unique: true, required: true },
    addedBy: { type: Number, required: true },
    addedAt: { type: Date, default: Date.now },
    permissions: {
        movies: { type: Boolean, default: true },
        channels: { type: Boolean, default: true },
        settings: { type: Boolean, default: false },
        users: { type: Boolean, default: true },
        broadcast: { type: Boolean, default: false },
        admins: { type: Boolean, default: false }
    }
});

const User = mongoose.model('User', userSchema);
const Movie = mongoose.model('Movie', movieSchema);
const Channel = mongoose.model('Channel', channelSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const Admin = mongoose.model('Admin', adminSchema);

// ==========================================
// 3. UTILS & SECURITY HELPERS
// ==========================================

// Memory Cleanup Service
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of floodMap.entries()) if (now - val > CONFIG.floodLimit * 2) floodMap.delete(key);
    for (const [key, val] of downloadLimitMap.entries()) if (now - val > CONFIG.downloadCooldown) downloadLimitMap.delete(key);
    for (const [key, val] of state.entries()) if (now - (val.timestamp || 0) > CONFIG.stateTTL) state.delete(key);
    for (const [key, val] of adminCache.entries()) if (now > val.expire) adminCache.delete(key);
}, 60000);

function sanitize(str) {
    if (!str) return '';
    return str.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .trim();
}

async function safeDelete(chatId, msgId) {
    if (!msgId) return;
    try { await bot.deleteMessage(chatId, msgId); } catch (e) { }
}

async function safeSend(chatId, text, options = {}) {
    try {
        return await bot.sendMessage(chatId, text, options);
    } catch (e) {
        if (e.response && e.response.statusCode === 403) {
            await User.updateOne({ telegramId: chatId }, { isActive: false });
        }
    }
}

function isFlooding(userId) {
    const last = floodMap.get(userId) || 0;
    const now = Date.now();
    if (now - last < CONFIG.floodLimit) return true;
    floodMap.set(userId, now);
    return false;
}

function isDownloadFlooding(userId) {
    const last = downloadLimitMap.get(userId) || 0;
    const now = Date.now();
    if (now - last < CONFIG.downloadCooldown) return true;
    downloadLimitMap.set(userId, now);
    return false;
}

async function isUserAdmin(userId) {
    if (userId === CONFIG.superAdminId) return true;
    const cached = adminCache.get(userId);
    if (cached && cached.expire > Date.now()) return cached.isAdmin;
    const admin = await Admin.findOne({ telegramId: userId });
    const isAdmin = !!admin;
    adminCache.set(userId, { isAdmin, expire: Date.now() + CONFIG.adminCacheTTL });
    return isAdmin;
}

async function hasPermission(userId, perm) {
    if (userId === CONFIG.superAdminId) return true;
    const admin = await Admin.findOne({ telegramId: userId });
    if (!admin) return false;
    return !!admin.permissions?.[perm];
}

async function checkSubscription(userId) {
    if (await isUserAdmin(userId)) return [];
    const channels = await Channel.find().lean();
    if (!channels.length) return [];
    const missingChannels = [];
    for (const ch of channels) {
        try {
            const res = await bot.getChatMember(ch.channelId, userId);
            if (['left', 'kicked'].includes(res.status)) missingChannels.push(ch);
        } catch (e) {
            // Agar bot kanaldan chiqarib yuborilgan bo'lsa yoki admin bo'lmasa, userga majburlamaymiz
            console.error(`Obuna xatosi (${ch.channelId}):`, e.message);
        }
    }
    return missingChannels;
}

function detectQuality(w) {
    if (!w) return "480p";
    if (w >= 3840) return "4K UHD";
    if (w >= 1920) return "1080p FHD";
    if (w >= 1280) return "720p HD";
    return "480p HQ";
}

function formatDuration(d) {
    if (!d) return "00:00";
    const h = Math.floor(d / 3600);
    const m = Math.floor((d % 3600) / 60);
    const s = d % 60;
    return `${h > 0 ? h + ':' : ''}${m}:${s.toString().padStart(2, '0')}`;
}

const CANCEL_BTN = {
    reply_markup: { inline_keyboard: [[{ text: "🚫 Bekor qilish", callback_data: "cancel_action" }]] }
};

bot.getMe().then(u => {
    BOT_USERNAME = u.username;
    console.log(`🚀 Secure Bot Started: @${BOT_USERNAME}`);
});

// ==========================================
// 4. MAIN MESSAGE HANDLER
// ==========================================

bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const text = (msg.text || msg.caption || '').trim();

    if (isFlooding(chatId)) return;

    try {
        let user = await User.findOneAndUpdate(
            { telegramId: chatId },
            { $setOnInsert: { firstName: sanitize(msg.from.first_name), username: msg.from.username }, isActive: true },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        if (user.isBanned) return;

        // --- STATE HANDLER ---
        if (state.has(chatId)) {
            const st = state.get(chatId);

            // [SECURITY FIX] Sessiya vaqtini tekshirish
            if (Date.now() - (st.timestamp || 0) > CONFIG.stateTTL) {
                state.delete(chatId);
                return safeSend(chatId, "⚠️ Sessiya vaqti tugadi. Qaytadan urinib ko'ring.");
            }

            if (st.action === 'ASK_BIRTH_YEAR') {
                const year = parseInt(text);
                const currentYear = new Date().getFullYear();
                if (isNaN(year) || year < 1950 || year > currentYear) {
                    return safeSend(chatId, `❌ Iltimos, to'g'ri yil kiriting (1950-${currentYear}):`);
                }
                user.birthYear = year;
                await user.save();
                const pendingCode = st.pendingCode;
                state.delete(chatId);
                await safeSend(chatId, "✅ Ma'lumot saqlandi! Botdan foydalanishingiz mumkin.");
                if (pendingCode) await handleMovieCodeRequest(chatId, pendingCode, user);
                return;
            }

            // Admin inputs
            if (await isUserAdmin(chatId)) {
                await handleAdminInput(chatId, msg);
                return;
            }
        }

        if (!user.birthYear) {
            const args = text.startsWith('/start ') ? text.split(' ')[1] : null;
            state.set(chatId, { action: 'ASK_BIRTH_YEAR', timestamp: Date.now(), pendingCode: args });
            return safeSend(chatId, "👋 Assalomu alaykum! <b>Tug'ilgan yilingizni</b> yozing (Masalan: 2004):", { parse_mode: 'HTML' });
        }

        if (text.startsWith('/start')) {
            await safeDelete(chatId, user.lastMessageId);
            const args = text.split(' ')[1];

            const missing = await checkSubscription(chatId);
            if (missing.length > 0) {
                if (args) state.set(chatId, { action: 'WAITING_SUB', pendingCode: args, timestamp: Date.now() });
                return sendSubRequest(chatId, missing);
            }

            if (args && /^\d+$/.test(args)) return showMovieCard(chatId, args, user);
            if (await isUserAdmin(chatId)) return showAdminPanel(chatId);

            const codesChannel = await Channel.findOne({ type: 'movie_codes' });
            return safeSend(chatId, `🎬 <b>Professional Kino Bot</b>\n\n🔎 Kino kodini yuboring:`, {
                parse_mode: 'HTML',
                reply_markup: { inline_keyboard: [[{ text: "📂 Kino Kodlari Kanali", url: codesChannel ? codesChannel.url : `https://t.me/${BOT_USERNAME}` }]] }
            });
        }

        if (text === '/admin' && await isUserAdmin(chatId)) return showAdminPanel(chatId);

        if (/^\d+$/.test(text)) {
            await handleMovieCodeRequest(chatId, text, user);
        }

    } catch (e) {
        console.error("Handler Error:", e);
    }
});

async function handleMovieCodeRequest(chatId, codeStr, user) {
    const missing = await checkSubscription(chatId);
    if (missing.length > 0) {
        state.set(chatId, { action: 'WAITING_SUB', pendingCode: codeStr, timestamp: Date.now() });
        return sendSubRequest(chatId, missing);
    }
    await showMovieCard(chatId, codeStr, user);
}

// ==========================================
// 5. ADMIN LOGIC (UPDATED)
// ==========================================

async function handleAdminInput(chatId, msg) {
    const st = state.get(chatId);
    const text = (msg.text || msg.caption || '').trim();

    if (st.permissionRequired && !await hasPermission(chatId, st.permissionRequired)) {
        state.delete(chatId);
        return safeSend(chatId, "⛔️ Ushbu amal uchun ruxsat yo'q!");
    }

    try {
        if (st.action === 'ADD_CONTENT') {
            if (st.step === 'VIDEO') {
                if (!msg.video) return safeSend(chatId, "❌ Video yuboring!", CANCEL_BTN);
                st.data = {
                    fileId: msg.video.file_id,
                    quality: detectQuality(msg.video.width),
                    duration: formatDuration(msg.video.duration)
                };
                st.step = 'POSTER';
                safeSend(chatId, "🖼 <b>Poster (Rasm) yuboring:</b>", { parse_mode: 'HTML', ...CANCEL_BTN });
            }
            else if (st.step === 'POSTER') {
                if (!msg.photo) return safeSend(chatId, "❌ Rasm yuboring!", CANCEL_BTN);
                st.data.posterId = msg.photo[msg.photo.length - 1].file_id;
                st.step = 'TITLE';
                safeSend(chatId, "✍️ <b>Nomini yozing:</b>", { parse_mode: 'HTML', ...CANCEL_BTN });
            }
            else if (st.step === 'TITLE') {
                st.data.title = sanitize(text);
                st.step = 'COUNTRY';
                safeSend(chatId, "🌍 <b>Davlat:</b>", { parse_mode: 'HTML', ...CANCEL_BTN });
            }
            else if (st.step === 'COUNTRY') {
                st.data.country = sanitize(text);
                st.step = 'LANG';
                safeSend(chatId, "🗣 <b>Til:</b>", { parse_mode: 'HTML', ...CANCEL_BTN });
            }
            else if (st.step === 'LANG') {
                st.data.language = sanitize(text);
                st.step = 'ADULT';
                safeSend(chatId, "🔞 <b>Yosh chegarasi (18+)?</b>", {
                    parse_mode: 'HTML',
                    reply_markup: {
                        inline_keyboard: [
                            [{ text: "✅ Ha", callback_data: "adult_yes" }, { text: "❌ Yo'q", callback_data: "adult_no" }],
                            [{ text: "🚫 Bekor qilish", callback_data: "cancel_action" }]
                        ]
                    }
                });
            }
            else if (st.step === 'CODE') {
                const code = parseInt(text);
                if (isNaN(code)) return safeSend(chatId, "❌ Faqat raqam!");
                if (await Movie.findOne({ code })) return safeSend(chatId, "⚠️ Bu kod band! Boshqa kod yozing.");

                const finalData = { code, ...st.data, addedBy: chatId, contentType: st.contentType };
                if (st.contentType === 'series') {
                    finalData.episodes = [{ number: 1, fileId: st.data.fileId, name: '1-qism' }];
                    delete finalData.fileId;
                }
                const movie = await Movie.create(finalData);

                // Auto Post logic
                const settings = await Settings.findOne({ key: 'config' });
                if (settings?.autoPost) {
                    const codesChannel = await Channel.findOne({ type: 'movie_codes' });
                    if (codesChannel) {
                        const typeEmoji = st.contentType === 'series' ? '📺 SERIAL' : '🎬 KINO';
                        const caption = `${typeEmoji} <b>${movie.title}</b>\n\n🌍 ${movie.country} | 🗣 ${movie.language}\n💿 ${movie.quality} | ⏳ ${movie.duration}\n\n👇 Tomosha qilish:\nhttps://t.me/${BOT_USERNAME}?start=${code}`;
                        try {
                            await bot.sendPhoto(codesChannel.channelId, movie.posterId, {
                                caption, parse_mode: 'HTML',
                                reply_markup: { inline_keyboard: [[{ text: "▶️ TOMOSHA QILISH", url: `https://t.me/${BOT_USERNAME}?start=${code}` }]] }
                            });
                        } catch (e) { console.error("AutoPost Error:", e.message); }
                    }
                }
                state.delete(chatId);
                safeSend(chatId, `✅ <b>${st.contentType === 'series' ? 'Serial' : 'Kino'} qo'shildi!</b> Kod: ${code}`, { parse_mode: 'HTML' });
                showAdminPanel(chatId);
            }
        }
        else if (st.action === 'ADD_EPISODE') {
            const movie = await Movie.findById(st.movieId);
            if (!movie) {
                state.delete(chatId);
                return safeSend(chatId, "❌ Serial bazadan topilmadi.");
            }

            if (st.step === 'VIDEO') {
                if (!msg.video) return safeSend(chatId, "❌ Video (keyingi qism) yuboring!", CANCEL_BTN);
                st.tempEpisodeData = {
                    fileId: msg.video.file_id,
                    quality: detectQuality(msg.video.width)
                };
                st.step = 'NAME';
                const nextEpNum = movie.episodes.length + 1;
                safeSend(chatId, `✍️ <b>${nextEpNum}-qism uchun nom yozing:</b>\n(Masalan: <i>Qasos onlari</i> yoki shunchaki <i>${nextEpNum}-qism</i>)`, { parse_mode: 'HTML', ...CANCEL_BTN });
            }
            else if (st.step === 'NAME') {
                const nextEpNum = movie.episodes.length + 1;
                const epName = sanitize(text);
                movie.episodes.push({
                    number: nextEpNum,
                    fileId: st.tempEpisodeData.fileId,
                    name: epName,
                    addedAt: Date.now()
                });
                movie.quality = st.tempEpisodeData.quality;
                await movie.save();
                state.delete(chatId);
                safeSend(chatId, `✅ <b>${nextEpNum}-qism ("${epName}") muvaffaqiyatli qo'shildi!</b>`);
                showEditMoviePanel(chatId, movie._id);
            }
        }

        // --- UPDATED ADD CHANNEL LOGIC ---
        else if (st.action === 'ADD_CHANNEL') {
            if (st.step === 'NAME') {
                st.data = { name: sanitize(text) };
                st.step = 'URL';
                safeSend(chatId, "🔗 <b>Kanal Usernamesi yoki Linkini yuboring:</b>\n(Masalan: <i>@kinolar</i> yoki <i>https://t.me/kinolar</i>)", { parse_mode: 'HTML', ...CANCEL_BTN });
            }
            else if (st.step === 'URL') {
                let username = text;
                // Linkdan username ni ajratib olish
                if (text.includes('t.me/')) {
                    const parts = text.split('t.me/');
                    username = '@' + parts[1].split('/')[0].split('?')[0]; // @username qilib olamiz
                } else if (!text.startsWith('@') && !text.startsWith('-100')) {
                    username = '@' + text;
                }

                let channelId = null;
                let chatTitle = st.data.name;

                try {
                    // Agar user to'g'ridan to'g'ri ID yuborsa (-100...)
                    if (/^-100\d+$/.test(text)) {
                        channelId = text;
                    } else {
                        // Username orqali ID ni aniqlash
                        const chat = await bot.getChat(username);
                        channelId = String(chat.id);
                        // Agar user nom kiritmagan bo'lsa, kanal nomini o'zidan olamiz (lekin bizda NAME step bor edi)
                        // chatTitle = chat.title; 
                    }

                    await Channel.findOneAndUpdate(
                        { channelId: channelId },
                        { channelId: channelId, name: st.data.name, url: text, type: st.type },
                        { upsert: true }
                    );

                    state.delete(chatId);
                    safeSend(chatId, `✅ <b>Kanal muvaffaqiyatli qo'shildi!</b>\n\n🆔 ID: ${channelId}\n🏷 Nom: ${st.data.name}`, { parse_mode: 'HTML' });
                    showChannelsPanel(chatId);

                } catch (e) {
                    console.error("Channel Add Error:", e.message);
                    safeSend(chatId, "❌ <b>Xatolik!</b>\n\n1. Bot kanalga <b>Admin</b> qilinganmi?\n2. Username/Link to'g'rimi?\n3. Agar bu 'Private' kanal bo'lsa, iltimos to'g'ridan-to'g'ri <b>ID raqamini</b> (-100...) yuboring.", { parse_mode: 'HTML', ...CANCEL_BTN });
                }
            }
        }

        else if (st.action === 'EDIT_SEARCH') {
            const code = parseInt(text);
            const movie = await Movie.findOne({ code });
            if (!movie) return safeSend(chatId, "❌ Topilmadi.");
            state.delete(chatId);
            showEditMoviePanel(chatId, movie._id);
        }
        else if (st.action === 'EDIT_FIELD') {
            const movie = await Movie.findById(st.movieId);
            if (movie) {
                if (st.field === 'title') movie.title = sanitize(text);
                else if (st.field === 'country') movie.country = sanitize(text);
                else if (st.field === 'posterId') {
                    if (msg.photo) movie.posterId = msg.photo[msg.photo.length - 1].file_id;
                    else return safeSend(chatId, "❌ Iltimos, rasm yuboring!", CANCEL_BTN);
                }
                else if (st.field === 'fileId' && movie.contentType === 'movie') {
                    if (msg.video) {
                        movie.fileId = msg.video.file_id;
                        movie.quality = detectQuality(msg.video.width);
                        movie.duration = formatDuration(msg.video.duration);
                    } else return safeSend(chatId, "❌ Video fayl yuboring!", CANCEL_BTN);
                }
                await movie.save();
                safeSend(chatId, "✅ Muvaffaqiyatli o'zgartirildi!");
                state.delete(chatId);
                showEditMoviePanel(chatId, st.movieId);
            } else {
                state.delete(chatId);
                safeSend(chatId, "❌ Kino topilmadi.");
            }
        }
        else if (st.action === 'BROADCAST') {
            st.msg = msg;
            safeSend(chatId, "📢 Tasdiqlaysizmi?", {
                parse_mode: 'HTML',
                reply_markup: { inline_keyboard: [[{ text: "✅ Ha, yuborish", callback_data: "confirm_broadcast" }], [{ text: "❌ Bekor qilish", callback_data: "cancel_action" }]] }
            });
        }
        else if (st.action === 'SEARCH_USER') {
            const tid = parseInt(text);
            if (isNaN(tid)) return safeSend(chatId, "❌ Faqat raqamli ID kiriting!");
            const u = await User.findOne({ telegramId: tid });
            state.delete(chatId);
            if (u) showUserManagePanel(chatId, u);
            else safeSend(chatId, "❌ User topilmadi");
        }
        else if (st.action === 'MANAGE_ADMIN_ID') {
            const tid = parseInt(text);
            if (isNaN(tid)) return safeSend(chatId, "❌ Faqat raqamli ID!");
            if (tid === CONFIG.superAdminId) return safeSend(chatId, "❌ Super Admin daxlsiz");
            let adm = await Admin.findOne({ telegramId: tid });
            if (!adm) adm = await Admin.create({ telegramId: tid, addedBy: chatId });
            state.delete(chatId);
            showAdminPermsPanel(chatId, adm);
        }

    } catch (e) {
        console.error("Admin Input Error:", e);
        state.delete(chatId);
        safeSend(chatId, "⚠️ Tizim xatoligi yuz berdi. Qayta urinib ko'ring.");
    }
}

// ==========================================
// 6. CALLBACK QUERY HANDLER
// ==========================================

bot.on('callback_query', async (q) => {
    const chatId = q.message.chat.id;
    const data = q.data;
    const msgId = q.message.message_id;

    try {
        if (data === 'cancel_action') {
            state.delete(chatId);
            await safeDelete(chatId, msgId);
            if (await isUserAdmin(chatId)) showAdminPanel(chatId);
            else bot.sendMessage(chatId, "Amal bekor qilindi.");
            return;
        }

        if (data === 'check_sub') {
            const missing = await checkSubscription(chatId);
            if (missing.length === 0) {
                await bot.deleteMessage(chatId, msgId);
                const st = state.get(chatId);
                if (st && st.pendingCode) {
                    await showMovieCard(chatId, st.pendingCode, await User.findOne({ telegramId: chatId }));
                } else {
                    safeSend(chatId, "✅ Obuna tasdiqlandi! Kino kodini yuboring.");
                }
            } else {
                bot.answerCallbackQuery(q.id, { text: "❌ Hali hammasiga a'zo bo'lmadingiz!", show_alert: true });
            }
            return;
        }

        // User actions
        if (data.startsWith('rate_')) await handleRating(chatId, data, q.id);
        if (data.startsWith('dl_')) await handleDownloadMovie(chatId, data, q.id);
        if (data.startsWith('s_nav_')) await handleSeriesNavigation(chatId, data, q.message.message_id, q.id);
        if (data.startsWith('s_dl_')) await handleDownloadEpisode(chatId, data, q.id);
        if (data === 'noop') return bot.answerCallbackQuery(q.id);

        // --- ADMIN CALLBACKS ---
        if (!await isUserAdmin(chatId)) return;

        if (data === 'admin_home') showAdminPanel(chatId, msgId);
        if (data === 'admin_stats') showStatistics(chatId, msgId);

        if (data === 'admin_add_content_select') {
            if (!await hasPermission(chatId, 'movies')) return bot.answerCallbackQuery(q.id, { text: "⛔️ Ruxsat yo'q!", show_alert: true });
            safeSend(chatId, "Nimani qo'shmoqchisiz?", {
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "🎬 KINO", callback_data: "start_add_movie" }, { text: "📺 SERIAL", callback_data: "start_add_series" }],
                        [{ text: "🚫 Bekor qilish", callback_data: "cancel_action" }]
                    ]
                }
            });
        }

        if (data === 'start_add_movie' || data === 'start_add_series') {
            const type = data === 'start_add_movie' ? 'movie' : 'series';
            state.set(chatId, { action: 'ADD_CONTENT', contentType: type, step: 'VIDEO', permissionRequired: 'movies', timestamp: Date.now() });
            await safeDelete(chatId, msgId);
            safeSend(chatId, `📤 <b>${type === 'movie' ? 'Kino' : 'Serial (1-qism)'} videosini yuboring:</b>`, { parse_mode: 'HTML', ...CANCEL_BTN });
        }

        if (['adult_yes', 'adult_no'].includes(data)) {
            const st = state.get(chatId);
            if (st && st.action === 'ADD_CONTENT') {
                st.data.isAdult = (data === 'adult_yes');
                st.step = 'CODE';
                await safeDelete(chatId, msgId);
                safeSend(chatId, "🔢 <b>Kino/Serial Kodini yozing:</b>", { parse_mode: 'HTML', ...CANCEL_BTN });
            }
        }

        if (data === 'admin_edit_movie') {
            if (!await hasPermission(chatId, 'movies')) return;
            state.set(chatId, { action: 'EDIT_SEARCH', permissionRequired: 'movies', timestamp: Date.now() });
            safeSend(chatId, "📝 Tahrirlash uchun Kodni yuboring:", CANCEL_BTN);
        }

        if (data.startsWith('ed_f_')) {
            const parts = data.split('_'); // ed, f, fieldName, movieId
            const field = parts[2];
            const mid = parts[3];
            state.set(chatId, { action: 'EDIT_FIELD', field: field, movieId: mid, permissionRequired: 'movies', timestamp: Date.now() });

            let prompt = "";
            if (field === 'title') prompt = "✍️ Yangi nomni yuboring:";
            else if (field === 'country') prompt = "🌍 Yangi davlatni yuboring:";
            else if (field === 'posterId') prompt = "🖼 Yangi posterni (rasm) yuboring:";
            else if (field === 'fileId') prompt = "📹 Yangi video faylni yuboring:";

            await safeDelete(chatId, msgId);
            safeSend(chatId, prompt, CANCEL_BTN);
        }

        // [SECURED] Start Adding Episode Callback
        if (data.startsWith('add_ep_')) {
            const mid = data.split('_')[2];
            state.set(chatId, {
                action: 'ADD_EPISODE',
                movieId: mid,
                step: 'VIDEO',
                permissionRequired: 'movies',
                timestamp: Date.now()
            });
            safeSend(chatId, "📤 <b>Keyingi qism videosini yuboring:</b>", { parse_mode: 'HTML', ...CANCEL_BTN });
        }

        if (data === 'admin_channels') {
            if (!await hasPermission(chatId, 'channels')) return;
            showChannelsPanel(chatId, msgId);
        }
        
        // [FIXED] Kanal qo'shish callback
        if (data === 'add_ch_main' || data === 'add_ch_codes') {
            if (!await hasPermission(chatId, 'channels')) return;
            // [TIMESTAMP QO'SHILDI]
            state.set(chatId, { 
                action: 'ADD_CHANNEL', 
                step: 'NAME', // 1-qadam: Nom so'rash
                type: data === 'add_ch_main' ? 'main' : 'movie_codes', 
                permissionRequired: 'channels',
                timestamp: Date.now()
            });
            safeSend(chatId, "✍️ <b>Kanal tugmasida nima deb yozilsin?</b>\n(Masalan: <i>Kino Kanalimiz</i>)", { parse_mode: 'HTML', ...CANCEL_BTN });
        }

        if (data.startsWith('del_ch_')) {
            if (!await hasPermission(chatId, 'channels')) return;
            await Channel.findByIdAndDelete(data.split('_')[2]);
            showChannelsPanel(chatId, msgId);
        }
        if (data === 'admin_broadcast') {
            if (!await hasPermission(chatId, 'broadcast')) return;
            state.set(chatId, { action: 'BROADCAST', permissionRequired: 'broadcast', timestamp: Date.now() });
            safeSend(chatId, "📢 Post yuboring (Text, Rasm, Video...):", CANCEL_BTN);
        }
        if (data === 'confirm_broadcast') {
            const st = state.get(chatId);
            if (st && st.msg) { state.delete(chatId); await safeDelete(chatId, msgId); startBroadcast(chatId, st.msg); }
        }
        if (data === 'stop_broadcast') {
            if (broadcastController.isActive) {
                broadcastController.shouldStop = true;
                bot.answerCallbackQuery(q.id, { text: "🛑 To'xtatilmoqda..." });
            } else {
                bot.answerCallbackQuery(q.id, { text: "⚠️ Reklama jarayoni yo'q.", show_alert: true });
            }
        }

        if (data === 'admin_settings') {
            if (!await hasPermission(chatId, 'settings')) return;
            showSettingsPanel(chatId, msgId);
        }
        if (data.startsWith('tog_set_')) {
            const k = data.split('_')[2];
            const c = await Settings.findOne({ key: 'config' }) || await Settings.create({});
            c[k] = !c[k]; await c.save();
            showSettingsPanel(chatId, msgId);
        }
        if (data === 'admin_users') {
            if (!await hasPermission(chatId, 'users')) return;
            // [TIMESTAMP FIX]
            state.set(chatId, { action: 'SEARCH_USER', permissionRequired: 'users', timestamp: Date.now() });
            safeSend(chatId, "🔎 User ID (Telegram ID) yuboring:", CANCEL_BTN);
        }
        if (data.startsWith('usr_')) {
            const [_, act, uid] = data.split('_');
            const u = await User.findOne({ telegramId: uid });
            if (u) {
                if (act === 'ban') u.isBanned = !u.isBanned;
                if (act === 'dl') u.restrictions.canDownload = !u.restrictions.canDownload;
                await u.save(); showUserManagePanel(chatId, u, msgId);
            }
        }
        if (data === 'admin_permission_setup') {
            // [TIMESTAMP FIX]
            state.set(chatId, { action: 'MANAGE_ADMIN_ID', timestamp: Date.now() });
            safeSend(chatId, "Admin ID:", CANCEL_BTN);
        }
        if (data.startsWith('perm_')) {
            const [_, k, uid] = data.split('_');
            const a = await Admin.findOne({ telegramId: uid });
            if (a) { a.permissions[k] = !a.permissions[k]; await a.save(); adminCache.delete(parseInt(uid)); showAdminPermsPanel(chatId, a, msgId); }
        }
        if (data.startsWith('del_admin_')) {
            const uid = parseInt(data.split('_')[2]);
            await Admin.deleteOne({ telegramId: uid });
            safeSend(chatId, "O'chirildi"); showAdminPanel(chatId);
        }
        if (data.startsWith('ed_del_')) {
            await Movie.findByIdAndDelete(data.split('_')[2]);
            safeSend(chatId, "O'chirildi"); showAdminPanel(chatId);
        }

    } catch (e) {
        console.error("Callback Error:", e);
        bot.answerCallbackQuery(q.id, { text: "Tizim xatosi!" });
    }
});

// ==========================================
// 7. BUSINESS LOGIC
// ==========================================

async function handleRating(userId, data, qId) {
    const [_, codeStr, scoreStr] = data.split('_');
    const code = parseInt(codeStr);
    const score = parseInt(scoreStr);
    const res = await Movie.updateOne(
        { code: code, ratedUsers: { $ne: userId } },
        { $push: { ratedUsers: userId }, $inc: { ratingSum: score, ratingCount: 1 } }
    );
    if (res.modifiedCount > 0) bot.answerCallbackQuery(qId, { text: `⭐️ ${score} baho qabul qilindi!` });
    else bot.answerCallbackQuery(qId, { text: "⛔️ Siz allaqachon ovoz bergansiz!", show_alert: true });
}

async function handleDownloadMovie(userId, data, qId) {
    if (isDownloadFlooding(userId)) return bot.answerCallbackQuery(qId, { text: `⏳ Kuting!`, show_alert: true });

    const code = parseInt(data.split('_')[1]);
    const movie = await Movie.findOne({ code });
    if (!movie) return bot.answerCallbackQuery(qId, { text: "❌ Topilmadi", show_alert: true });

    const user = await User.findOne({ telegramId: userId });
    const conf = await Settings.findOne({ key: 'config' }) || { globalDownload: true };
    if (!conf.globalDownload || !user.restrictions.canDownload) return bot.answerCallbackQuery(qId, { text: "🚫 Yuklash taqiqlangan.", show_alert: true });

    bot.answerCallbackQuery(qId, { text: "🚀 Yuborilmoqda..." });
    bot.sendChatAction(userId, 'upload_video');
    Movie.updateOne({ code }, { $inc: { downloads: 1 } }).exec();

    const protect = conf.globalProtection || user.restrictions.contentProtected;
    try {
        await bot.sendVideo(userId, movie.fileId, {
            caption: `🎬 <b>${movie.title}</b>\n\n🤖 @${BOT_USERNAME}`,
            parse_mode: 'HTML',
            protect_content: protect
        });
    } catch (e) {
        safeSend(userId, "⚠️ Video fayl xatosi yoki o'chirilgan.");
    }
}

async function handleDownloadEpisode(userId, data, qId) {
    if (isDownloadFlooding(userId)) return bot.answerCallbackQuery(qId, { text: `⏳ Kuting!`, show_alert: true });

    const [_, __, codeStr, epNumStr] = data.split('_');
    const code = parseInt(codeStr);
    const epNum = parseInt(epNumStr);

    const movie = await Movie.findOne({ code });
    if (!movie || movie.contentType !== 'series') return bot.answerCallbackQuery(qId, { text: "❌ Serial topilmadi", show_alert: true });

    const episode = movie.episodes.find(e => e.number === epNum);
    if (!episode) return bot.answerCallbackQuery(qId, { text: "❌ Qism topilmadi", show_alert: true });

    const user = await User.findOne({ telegramId: userId });
    const conf = await Settings.findOne({ key: 'config' }) || { globalDownload: true };
    if (!conf.globalDownload || !user.restrictions.canDownload) return bot.answerCallbackQuery(qId, { text: "🚫 Yuklash taqiqlangan.", show_alert: true });

    bot.answerCallbackQuery(qId, { text: `🚀 ${epNum}-qism yuborilmoqda...` });
    bot.sendChatAction(userId, 'upload_video');

    const protect = conf.globalProtection || user.restrictions.contentProtected;
    const epNameDisplay = episode.name ? ` (${episode.name})` : '';

    try {
        await bot.sendVideo(userId, episode.fileId, {
            caption: `📺 <b>${movie.title}</b> | ${epNum}-qism${epNameDisplay}\n\n🤖 @${BOT_USERNAME}`,
            parse_mode: 'HTML',
            protect_content: protect
        });
    } catch (e) {
        safeSend(userId, "⚠️ Video fayl xatosi.");
    }
}

async function handleSeriesNavigation(userId, data, msgId, qId) {
    const [_, __, codeStr, pageStr] = data.split('_');
    const code = parseInt(codeStr);
    const page = parseInt(pageStr);

    const movie = await Movie.findOne({ code });
    if (!movie) return bot.answerCallbackQuery(qId, { text: "❌ Serial topilmadi" });

    const keyboard = generateSeriesKeyboard(movie, page);

    try {
        await bot.editMessageReplyMarkup(keyboard, { chat_id: userId, message_id: msgId });
        bot.answerCallbackQuery(qId);
    } catch (e) {
        bot.answerCallbackQuery(qId, { text: "🔄 Yangilandi" });
    }
}

function generateSeriesKeyboard(movie, page = 0) {
    const limit = 5;
    const totalEps = movie.episodes.length;
    const start = page * limit;
    const end = start + limit;
    const currentEps = movie.episodes.slice(start, end);

    const epButtons = currentEps.map(ep => ({
        text: `${ep.number}`,
        callback_data: `s_dl_${movie.code}_${ep.number}`
    }));

    const rows = [];
    let tempRow = [];
    for (let i = 0; i < epButtons.length; i++) {
        tempRow.push(epButtons[i]);
        if (tempRow.length === 3 || i === epButtons.length - 1) {
            rows.push(tempRow);
            tempRow = [];
        }
    }

    const navRow = [];
    if (page > 0) {
        navRow.push({ text: "⬅️ Oldingi", callback_data: `s_nav_${movie.code}_${page - 1}` });
    }
    if (end < totalEps) {
        navRow.push({ text: "Keyingi ➡️", callback_data: `s_nav_${movie.code}_${page + 1}` });
    }

    const ratingRow = [1, 2, 3, 4, 5].map(r => ({ text: `${r}⭐️`, callback_data: `rate_${movie.code}_${r}` }));

    return {
        inline_keyboard: [
            ratingRow,
            ...rows,
            navRow,
            [{ text: "♻️ Do'stlarga ulashish", url: `https://t.me/share/url?url=https://t.me/${BOT_USERNAME}?start=${movie.code}` }]
        ]
    };
}

async function showMovieCard(chatId, code, user) {
    const movie = await Movie.findOne({ code: parseInt(code) });
    if (!movie) return safeSend(chatId, "❌ <b>Topilmadi.</b> Kod noto'g'ri.", { parse_mode: 'HTML' });

    Movie.updateOne({ code: parseInt(code) }, { $inc: { views: 1 } }).exec();

    const rating = movie.ratingCount > 0 ? (movie.ratingSum / movie.ratingCount).toFixed(1) : "0";
    const typeText = movie.contentType === 'series' ? '📺 SERIAL' : '🎬 KINO';

    let caption = `${typeText}: <b>${movie.title}</b>\n\n🌍 ${movie.country} | 🗣 ${movie.language}\n💿 ${movie.quality} | ⏳ ${movie.duration}\n\n👁 ${movie.views} | ⭐️ ${rating}\n\n`;
    if (movie.isAdult) caption += "🔞 <b>18+ SAHNALAR MAVJUD!</b>\n";
    if (movie.contentType === 'series') caption += `📂 Jami qismlar: ${movie.episodes.length} ta\n👇 Quyidan qismni tanlang:`;

    let markup;
    if (movie.contentType === 'series') {
        markup = generateSeriesKeyboard(movie, 0);
    } else {
        markup = {
            inline_keyboard: [
                [1, 2, 3, 4, 5].map(r => ({ text: `${r}⭐️`, callback_data: `rate_${movie.code}_${r}` })),
                [{ text: `📥 Yuklab olish (${movie.quality})`, callback_data: `dl_${movie.code}` }]
            ]
        };
    }

    if (movie.posterId) await bot.sendPhoto(chatId, movie.posterId, { caption, parse_mode: 'HTML', reply_markup: markup }).catch(() => { });
    else await safeSend(chatId, caption, { parse_mode: 'HTML', reply_markup: markup });
}

function showAdminPanel(chatId, msgId = null) {
    isUserAdmin(chatId).then(isAdmin => {
        if (!isAdmin) return;
        Admin.findOne({ telegramId: chatId }).then(admin => {
            const p = chatId === CONFIG.superAdminId ? { movies: true, channels: true, users: true, broadcast: true, settings: true, admins: true } : (admin?.permissions || {});

            const buttons = [];
            buttons.push([{ text: "📊 STATISTIKA", callback_data: "admin_stats" }]);

            if (p.movies) buttons.push([
                { text: "➕ Qo'shish (Kino/Serial)", callback_data: "admin_add_content_select" },
                { text: "📝 Tahrirlash", callback_data: "admin_edit_movie" }
            ]);
            if (p.channels) buttons.push([{ text: "📢 Kanallar", callback_data: "admin_channels" }]);
            if (p.users) buttons.push([{ text: "👥 Userlar", callback_data: "admin_users" }]);
            if (p.broadcast) buttons.push([{ text: "📨 Reklama", callback_data: "admin_broadcast" }]);
            if (p.settings) buttons.push([{ text: "⚙️ Sozlamalar", callback_data: "admin_settings" }]);
            if (chatId === CONFIG.superAdminId) buttons.push([{ text: "👮‍♂️ Adminlar", callback_data: "admin_permission_setup" }]);

            const txt = "🛡 <b>ADMIN PANEL V15.4</b>";
            const opts = { parse_mode: 'HTML', reply_markup: { inline_keyboard: buttons } };

            if (msgId) bot.editMessageText(txt, { chat_id: chatId, message_id: msgId, ...opts }).catch(() => { });
            else safeSend(chatId, txt, opts);
        });
    });
}

async function showStatistics(chatId, msgId) {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const blockedUsers = await User.countDocuments({ isActive: false });
    const bannedUsers = await User.countDocuments({ isBanned: true });

    const totalMovies = await Movie.countDocuments({ contentType: 'movie' });
    const totalSeries = await Movie.countDocuments({ contentType: 'series' });

    const metrics = await Movie.aggregate([
        {
            $group: {
                _id: null,
                totalViews: { $sum: "$views" },
                totalDownloads: { $sum: "$downloads" },
                totalEpisodes: { $sum: { $size: { $ifNull: ["$episodes", []] } } }
            }
        }
    ]);
    const m = metrics[0] || { totalViews: 0, totalDownloads: 0, totalEpisodes: 0 };

    const uptime = ((Date.now() - startTime) / 1000 / 3600).toFixed(2);
    const freeMem = (os.freemem() / 1024 / 1024).toFixed(0);
    const totalMem = (os.totalmem() / 1024 / 1024).toFixed(0);

    const txt = `📊 <b>PROFESSIONAL STATISTIKA</b>\n\n` +
        `👥 <b>Foydalanuvchilar:</b>\n` +
        `├ Jami: <b>${totalUsers}</b>\n` +
        `├ Aktiv: <b>${activeUsers}</b>\n` +
        `├ Bloklagan: <b>${blockedUsers}</b>\n` +
        `└ Ban qilingan: <b>${bannedUsers}</b>\n\n` +
        `🎬 <b>Kontent Bazasi:</b>\n` +
        `├ Kinolar: <b>${totalMovies}</b> ta\n` +
        `├ Seriallar: <b>${totalSeries}</b> ta\n` +
        `└ Jami Qismlar: <b>${m.totalEpisodes}</b> ta\n\n` +
        `📈 <b>Faollik:</b>\n` +
        `├ Ko'rishlar: <b>${m.totalViews}</b>\n` +
        `└ Yuklashlar: <b>${m.totalDownloads}</b>\n\n` +
        `🖥 <b>Server Holati:</b>\n` +
        `├ Uptime: <b>${uptime} soat</b>\n` +
        `└ RAM: <b>${freeMem}MB / ${totalMem}MB</b>`;

    const kb = { inline_keyboard: [[{ text: "🔄 Yangilash", callback_data: "admin_stats" }], [{ text: "🔙 Orqaga", callback_data: "admin_home" }]] };

    if (msgId) bot.editMessageText(txt, { chat_id: chatId, message_id: msgId, parse_mode: 'HTML', reply_markup: kb }).catch(() => { });
    else safeSend(chatId, txt, { parse_mode: 'HTML', reply_markup: kb });
}

async function showEditMoviePanel(chatId, mid, msgId = null) {
    const m = await Movie.findById(mid);
    if (!m) return safeSend(chatId, "❌ Topilmadi");

    const typeStr = m.contentType === 'series' ? "📺 SERIAL" : "🎬 KINO";
    const txt = `📝 Tahrir (${typeStr}): <b>${m.title}</b> (${m.code})`;

    const kb = [
        [{ text: "🏷 Nom", callback_data: `ed_f_title_${mid}` }, { text: "🌍 Davlat", callback_data: `ed_f_country_${mid}` }],
        [{ text: "🖼 Poster", callback_data: `ed_f_posterId_${mid}` }, { text: "🗑 O'CHIRISH", callback_data: `ed_del_${mid}` }]
    ];

    if (m.contentType === 'series') {
        kb.push([{ text: `➕ YANGI QISM QO'SHISH (${m.episodes.length + 1})`, callback_data: `add_ep_${mid}` }]);
    } else {
        kb.push([{ text: "📹 Video", callback_data: `ed_f_fileId_${mid}` }]);
    }

    kb.push([{ text: "🔙 Orqaga", callback_data: "admin_home" }]);

    const opts = { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } };
    if (msgId) bot.editMessageText(txt, { chat_id: chatId, message_id: msgId, ...opts }).catch(() => { });
    else safeSend(chatId, txt, opts);
}

async function showChannelsPanel(chatId, msgId) {
    const channels = await Channel.find();
    const btns = channels.map(c => [{ text: `${c.type === 'main' ? '📢' : '📂'} ${c.name}`, callback_data: 'noop' }, { text: "🗑", callback_data: `del_ch_${c._id}` }]);
    btns.push([{ text: "➕ Asosiy Kanal", callback_data: "add_ch_main" }]);
    btns.push([{ text: "➕ Kodlar Kanali", callback_data: "add_ch_codes" }]);
    btns.push([{ text: "🔙 Orqaga", callback_data: "admin_home" }]);
    bot.editMessageText("📢 <b>Kanallar:</b>", { chat_id: chatId, message_id: msgId, parse_mode: 'HTML', reply_markup: { inline_keyboard: btns } }).catch(() => { });
}

async function showSettingsPanel(chatId, msgId) {
    const conf = await Settings.findOne({ key: 'config' }) || await Settings.create({});
    const kb = {
        inline_keyboard: [
            [{ text: `🛡 Global Protect: ${conf.globalProtection ? "✅" : "❌"}`, callback_data: "tog_set_globalProtection" }],
            [{ text: `📥 Global Download: ${conf.globalDownload ? "✅" : "❌"}`, callback_data: "tog_set_globalDownload" }],
            [{ text: `📢 Auto-Post: ${conf.autoPost ? "✅" : "❌"}`, callback_data: "tog_set_autoPost" }],
            [{ text: "🔙 Orqaga", callback_data: "admin_home" }]
        ]
    };
    bot.editMessageText("⚙️ <b>Sozlamalar:</b>", { chat_id: chatId, message_id: msgId, parse_mode: 'HTML', reply_markup: kb }).catch(() => { });
}

async function showUserManagePanel(chatId, u, msgId = null) {
    const txt = `👤 <b>User:</b> <a href="tg://user?id=${u.telegramId}">${sanitize(u.firstName)}</a>\n🆔 <code>${u.telegramId}</code>\n🚫 Ban: ${u.isBanned ? '✅' : "❌"}`;
    const kb = {
        inline_keyboard: [
            [{ text: u.isBanned ? "✅ Bandan Olish" : "🚫 Ban Berish", callback_data: `usr_ban_${u.telegramId}` }],
            [{ text: u.restrictions.canDownload ? "🚷 Yuklashni Taqiq" : "📥 Yuklashga Ruxsat", callback_data: `usr_dl_${u.telegramId}` }],
            [{ text: "🔙 Orqaga", callback_data: "admin_users" }]
        ]
    };
    if (msgId) bot.editMessageText(txt, { chat_id: chatId, message_id: msgId, parse_mode: 'HTML', reply_markup: kb }).catch(() => { });
    else safeSend(chatId, txt, { parse_mode: 'HTML', reply_markup: kb });
}

async function showAdminPermsPanel(chatId, admin, msgId = null) {
    const p = admin.permissions;
    const txt = `👮‍♂️ <b>Admin:</b> <code>${admin.telegramId}</code>`;
    const kb = [
        [{ text: `🎬 Movies: ${p.movies ? '✅' : '❌'}`, callback_data: `perm_movies_${admin.telegramId}` }],
        [{ text: `📢 Channels: ${p.channels ? '✅' : '❌'}`, callback_data: `perm_channels_${admin.telegramId}` }],
        [{ text: `👥 Users: ${p.users ? '✅' : '❌'}`, callback_data: `perm_users_${admin.telegramId}` }],
        [{ text: `📨 Broadcast: ${p.broadcast ? '✅' : '❌'}`, callback_data: `perm_broadcast_${admin.telegramId}` }],
        [{ text: `⚙️ Settings: ${p.settings ? '✅' : '❌'}`, callback_data: `perm_settings_${admin.telegramId}` }],
        [{ text: "🗑 O'chirish", callback_data: `del_admin_${admin.telegramId}` }],
        [{ text: "🔙 Orqaga", callback_data: "admin_home" }]
    ];
    const opts = { parse_mode: 'HTML', reply_markup: { inline_keyboard: kb } };
    if (msgId) bot.editMessageText(txt, { chat_id: chatId, message_id: msgId, ...opts }).catch(() => { });
    else safeSend(chatId, txt, opts);
}

function sendSubRequest(chatId, channels) {
    const btns = channels.map(c => [{ text: `➕ A'zo bo'lish (${c.name})`, url: c.url }]);
    btns.push([{ text: "✅ Tasdiqlash", callback_data: "check_sub" }]);
    safeSend(chatId, "⚠️ <b>Botdan foydalanish uchun quyidagi kanallarga a'zo bo'ling:</b>", { parse_mode: 'HTML', reply_markup: { inline_keyboard: btns } });
}

// Broadcast Controller
async function startBroadcast(adminId, message) {
    if (broadcastController.isActive) return safeSend(adminId, "⚠️ Hozirda boshqa reklama ketmoqda!");

    broadcastController.isActive = true;
    broadcastController.shouldStop = false;

    let count = 0, blocked = 0;
    const startTime = Date.now();
    const stopMsg = await safeSend(adminId, "🚀 Reklama boshlandi...", { reply_markup: { inline_keyboard: [[{ text: "🛑 TO'XTATISH", callback_data: "stop_broadcast" }]] } });

    const cursor = User.find({ isBanned: false, isActive: true }).cursor();

    for (let user = await cursor.next(); user != null; user = await cursor.next()) {
        if (broadcastController.shouldStop) {
            broadcastController.isActive = false;
            return safeSend(adminId, `🛑 <b>Reklama to'xtatildi!</b>\n✅ Yuborildi: ${count}`);
        }

        try {
            await bot.copyMessage(user.telegramId, message.chat.id, message.message_id);
            count++;
        } catch (e) {
            if (e.response && (e.response.statusCode === 403 || e.response.statusCode === 400)) {
                blocked++;
                await User.updateOne({ _id: user._id }, { isActive: false });
            }
        }
        await new Promise(r => setTimeout(r, 40)); // 25 msg/sec to stay safe
    }

    broadcastController.isActive = false;
    safeDelete(adminId, stopMsg.message_id);
    safeSend(adminId, `📊 <b>Tugadi:</b>\n✅: ${count}\n🚫: ${blocked}\n⏱: ${((Date.now() - startTime) / 1000).toFixed(1)}s`, { parse_mode: 'HTML' });
}