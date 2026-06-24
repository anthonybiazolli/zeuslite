const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const xlsx = require('xlsx');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ storage: multer.memoryStorage() });

const API_URL = 'http://evolution-api:8080';
const GLOBAL_API_KEY = 'SuaChaveSecretaMaster123';
const JWT_SECRET = 'chave_secreta_super_segura_do_anthony';

const evolutionHeaders = {
    'apikey': GLOBAL_API_KEY,
    'Content-Type': 'application/json'
};

const USERS_FILE = path.join(__dirname, 'usuarios.json');
const CAMPAIGNS_FILE = path.join(__dirname, 'campanhas.json');
const AUDIT_FILE = path.join(__dirname, 'mensagens_apagadas.json');

function carregarDados(arquivo, padrao = []) {
    if (!fs.existsSync(arquivo)) fs.writeFileSync(arquivo, JSON.stringify(padrao, null, 2));
    return JSON.parse(fs.readFileSync(arquivo));
}

function salvarDados(arquivo, dados) {
    fs.writeFileSync(arquivo, JSON.stringify(dados, null, 2));
}

let usuarios = carregarDados(USERS_FILE, [
    { 
        usuario: 'zeusmaster', 
        senha: 'Z3usPr3m1um2026', 
        role: 'admin', 
        conexoesMax: 99, 
        limiteDiario: 999999,
        twoFactorSecret: null,
        twoFactorConfigured: false
    }
]);
let campanhas = carregarDados(CAMPAIGNS_FILE, []);
let msgsApagadas = carregarDados(AUDIT_FILE, []);

function formatarNumeroBrasil(numero) {
    if (!numero) return '';
    let limpo = numero.toString().replace(/\D/g, ''); 
    if (limpo.length === 10 || limpo.length === 11) return `55${limpo}`;
    return limpo;
}

function gerarIdUnico(instanciasAtivas) {
    const caracteres = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let id;
    let repetido = true;
    while(repetido) {
        id = '';
        for(let i=0; i < 6; i++) id += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
        repetido = instanciasAtivas.some(inst => inst.instance.instanceName.includes(id.toLowerCase()));
    }
    return id;
}

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ erro: 'Acesso restrito.' });
    jwt.verify(token.split(" ")[1], JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ erro: 'Sessão inválida.' });
        req.userContext = decoded;
        next();
    });
};

// ==========================================================
// SEGURANÇA E LOGIN MULTIFATOR (2FA)
// ==========================================================
app.post('/api/login/passo1', async (req, res) => {
    const { usuario, senha } = req.body;
    const userFound = usuarios.find(u => u.usuario === usuario && u.senha === senha);
    
    if (!userFound) return res.status(401).json({ sucesso: false, erro: 'Usuário ou senha incorretos!' });
    if (userFound.role === 'user' && userFound.deveAlterarSenha) return res.json({ sucesso: true, requerTrocaSenha: true, user: userFound.usuario });

    if (userFound.role === 'admin') {
        if (!userFound.twoFactorConfigured) {
            const secret = speakeasy.generateSecret({ name: `Zeus-Lite (${userFound.usuario})` });
            userFound.twoFactorSecret = secret.base32;
            salvarDados(USERS_FILE, usuarios);
            const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);
            return res.json({ sucesso: true, requer2FA: true, configurando2FA: true, qrCode: qrCodeDataUrl, secretCode: secret.base32, user: userFound.usuario });
        } else {
            return res.json({ sucesso: true, requer2FA: true, configurando2FA: false, user: userFound.usuario });
        }
    }
    const token = jwt.sign({ user: userFound.usuario, role: userFound.role }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ sucesso: true, token, role: userFound.role, user: userFound.usuario });
});

app.post('/api/login/verificar-2fa', (req, res) => {
    const { usuario, token2fa } = req.body;
    const userFound = usuarios.find(u => u.usuario === usuario);
    if (!userFound) return res.status(404).json({ erro: 'Usuário não localizado.' });

    const verificado = speakeasy.totp.verify({ secret: userFound.twoFactorSecret, encoding: 'base32', token: token2fa, window: 1 });
    if (verificado) {
        if (!userFound.twoFactorConfigured) { 
            userFound.twoFactorConfigured = true; 
            salvarDados(USERS_FILE, usuarios); 
        }
        const token = jwt.sign({ user: userFound.usuario, role: userFound.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ sucesso: true, token, role: userFound.role, user: userFound.usuario });
    } else {
        res.status(401).json({ sucesso: false, erro: 'Código inválido!' });
    }
});

app.post('/api/usuarios/alterar-senha-inicial', (req, res) => {
    const { usuario, novaSenha } = req.body;
    const userFound = usuarios.find(u => u.usuario === usuario);
    if (!userFound) return res.status(444).json({ erro: 'Usuário não encontrado.' });

    userFound.senha = novaSenha;
    userFound.deveAlterarSenha = false;
    usuarios = usuarios.map(u => u.usuario === usuario ? userFound : u);
    salvarDados(USERS_FILE, usuarios);

    const token = jwt.sign({ user: userFound.usuario, role: userFound.role }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ sucesso: true, token, role: userFound.role, user: userFound.usuario });
});

app.post('/api/admin/impersonate', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ erro: 'Acesso negado' });
    const token = authHeader.split(" ")[1];
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ erro: 'Ação restrita ao Admin.' });
        const targetUser = req.body.usuarioTarget;
        const userFound = usuarios.find(u => u.usuario === targetUser);
        if (!userFound) return res.status(404).json({ erro: 'Alvo inexistente.' });

        const novoToken = jwt.sign({ user: userFound.usuario, role: userFound.role, originalAdmin: decoded.user }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ sucesso: true, token: novoToken, user: userFound.usuario, role: userFound.role });
    });
});

app.get('/api/admin/usuarios', verificarToken, (req, res) => {
    if (req.userContext.role !== 'admin') return res.status(403).json({ erro: 'Negado.' });
    res.json({ sucesso: true, usuarios: usuarios.filter(u => u.role !== 'admin') });
});

app.post('/api/admin/usuarios/criar', verificarToken, (req, res) => {
    if (req.userContext.role !== 'admin') return res.status(403).json({ erro: 'Acesso negado.' });
    const { nome, usuario, senhaInicial, email, telefone, tipoUsuario, codigoInterno, conexoesMax, limiteDiario } = req.body;
    
    if (usuarios.find(u => u.usuario === usuario)) return res.json({ sucesso: false, erro: 'Login já cadastrado.' });
    
    usuarios.push({ 
        nome, usuario, senha: senhaInicial, email, telefone, tipoUsuario, codigoInterno,
        role: 'user', conexoesMax: parseInt(conexoesMax || 1), limiteDiario: parseInt(limiteDiario || 100),
        deveAlterarSenha: true 
    });
    salvarDados(USERS_FILE, usuarios);
    res.json({ sucesso: true });
});

// ==========================================================
// GESTÃO DE INSTÂNCIAS (QR / PIN)
// ==========================================================
app.get('/api/instancias', verificarToken, async (req, res) => {
    try {
        const response = await axios.get(`${API_URL}/instance/fetchInstances`, { headers: evolutionHeaders });
        const list = Array.isArray(response.data) ? response.data : [];
        const prefixoDono = req.userContext.user;

        const filtradas = list.filter(item => item.instance.instanceName.startsWith(prefixoDono)).map(item => {
            let idExibicao = item.instance.instanceName.split('-')[1] || item.instance.instanceName.replace(prefixoDono, '');
            return {
                nome: item.instance.instanceName,
                idExibicao: idExibicao.toUpperCase(),
                status: item.instance.status,
                numero: item.instance.owner ? item.instance.owner.replace('@s.whatsapp.net', '') : 'Aguardando Sincronização'
            };
        });
        res.json({ sucesso: true, instancias: filtradas, limites: usuarios.find(u => u.usuario === prefixoDono) });
    } catch (error) {
        res.json({ sucesso: true, instancias: [], limites: { conexoesMax: 1, limiteDiario: 100 } });
    }
});

app.post('/api/criar-instancia', verificarToken, async (req, res) => {
    const prefixoDono = req.userContext.user;
    const configUser = usuarios.find(u => u.usuario === prefixoDono);
    
    try {
        const responseCheck = await axios.get(`${API_URL}/instance/fetchInstances`, { headers: evolutionHeaders });
        const todas = Array.isArray(responseCheck.data) ? responseCheck.data : [];
        if (todas.filter(item => item.instance.instanceName.startsWith(prefixoDono)).length >= configUser.conexoesMax) {
            return res.json({ sucesso: false, erro: `Seu limite de conexões (${configUser.conexoesMax}) foi atingido.` });
        }
        
        const novoIdMaiusculo = gerarIdUnico(todas);
        const nomeCompletoInstancia = `${prefixoDono}-${novoIdMaiusculo.toLowerCase()}`;
        
        const response = await axios.post(`${API_URL}/instance/create`, { instanceName: nomeCompletoInstancia, qrcode: true, integration: "WHATSAPP-BAILEYS" }, { headers: evolutionHeaders });
        res.json({ sucesso: true, qrcode: response.data.qrcode.base64, idGerado: novoIdMaiusculo });
    } catch (error) { 
        res.json({ sucesso: false, erro: "Falha ao gerar canal na API." }); 
    }
});

app.post('/api/criar-instancia-pin', verificarToken, async (req, res) => {
    const prefixoDono = req.userContext.user;
    const configUser = usuarios.find(u => u.usuario === prefixoDono);
    
    try {
        const responseCheck = await axios.get(`${API_URL}/instance/fetchInstances`, { headers: evolutionHeaders });
        const todas = Array.isArray(responseCheck.data) ? responseCheck.data : [];
        if (todas.filter(item => item.instance.instanceName.startsWith(prefixoDono)).length >= configUser.conexoesMax) {
            return res.json({ sucesso: false, erro: `Limite atingido.` });
        }

        const { numeroTelefone } = req.body;
        const numeroFormatado = formatarNumeroBrasil(numeroTelefone);
        const novoIdMaiusculo = gerarIdUnico(todas);
        const nomeCompletoInstancia = `${prefixoDono}-${novoIdMaiusculo.toLowerCase()}`;

        await axios.post(`${API_URL}/instance/create`, { instanceName: nomeCompletoInstancia, qrcode: false, integration: "WHATSAPP-BAILEYS" }, { headers: evolutionHeaders });
        const connectResponse = await axios.get(`${API_URL}/instance/connect/${nomeCompletoInstancia}?number=${numeroFormatado}`, { headers: evolutionHeaders });
        
        let pinCode = connectResponse.data?.pairingCode || connectResponse.data?.code;
        if(pinCode) res.json({ sucesso: true, pairingCode: pinCode, idGerado: novoIdMaiusculo });
        else res.json({ sucesso: false, erro: "API não gerou PIN." });
    } catch (e) { 
        res.json({ sucesso: false, erro: "Falha no pareamento via PIN." }); 
    }
});

app.post('/api/instancia/logout', verificarToken, async (req, res) => {
    try { 
        await axios.post(`${API_URL}/instance/logout/${req.body.nomeInstancia}`, {}, { headers: evolutionHeaders }); 
        res.json({ sucesso: true }); 
    } catch (e) { 
        res.json({ sucesso: false, erro: 'Erro ao deslogar' }); 
    }
});

app.post('/api/instancia/deletar', verificarToken, async (req, res) => {
    try { 
        await axios.delete(`${API_URL}/instance/delete/${req.body.nomeInstancia}`, { headers: evolutionHeaders }); 
        res.json({ sucesso: true }); 
    } catch (e) { 
        res.json({ sucesso: false, erro: 'Erro ao excluir' }); 
    }
});

app.post('/api/instancia/reiniciar', verificarToken, async (req, res) => {
    try { 
        await axios.put(`${API_URL}/instance/restart/${req.body.nomeInstancia}`, {}, { headers: evolutionHeaders }); 
        res.json({ sucesso: true }); 
    } catch (e) { 
        res.json({ sucesso: false, erro: 'Erro ao reiniciar' }); 
    }
});

// ==========================================================
// PROXY DO CHAT AO VIVO BLINDADO CONTRA ERROS DA API
// ==========================================================
app.get('/api/chat/contatos', verificarToken, async (req, res) => {
    const { instancia } = req.query;
    if (!instancia || !instancia.startsWith(req.userContext.user)) return res.json({ sucesso: false, erro: 'Negado.' });

    try {
        const response = await axios.get(`${API_URL}/chat/findContacts/${instancia}`, { headers: evolutionHeaders });
        let dados = [];
        
        // Varredura em profundidade para achar onde a API injetou a lista
        if (Array.isArray(response.data)) {
            dados = response.data;
        } else if (response.data && typeof response.data === 'object') {
            dados = response.data.records || response.data.contacts || Object.values(response.data);
        }
        res.json({ sucesso: true, contatos: dados || [] });
    } catch (e) { 
        res.json({ sucesso: false, contatos: [] }); 
    }
});

app.get('/api/chat/conversas', verificarToken, async (req, res) => {
    const { instancia } = req.query;
    if (!instancia || !instancia.startsWith(req.userContext.user)) return res.json({ sucesso: false, erro: 'Negado.' });

    try {
        const response = await axios.get(`${API_URL}/chat/findChats/${instancia}`, { headers: evolutionHeaders });
        let dados = [];
        
        if (Array.isArray(response.data)) {
            dados = response.data;
        } else if (response.data && typeof response.data === 'object') {
            dados = response.data.records || response.data.chats || Object.values(response.data);
        }
        
        const dadosLimpos = (dados || []).map(chat => ({
            id: chat.id || chat.remoteJid || '',
            name: chat.name || chat.pushName || '',
            message: chat.message || null
        })).filter(c => c.id);

        res.json({ sucesso: true, conversas: dadosLimpos });
    } catch (error) { 
        res.json({ sucesso: false, conversas: [] }); 
    }
});

app.get('/api/chat/mensagens', verificarToken, async (req, res) => {
    const { instancia, remoteJid } = req.query;
    if (!instancia || !instancia.startsWith(req.userContext.user)) return res.json({ sucesso: false, erro: 'Negado.' });
    try {
        const response = await axios.post(`${API_URL}/chat/findMessages/${instancia}`, { where: { key: { remoteJid: remoteJid } }, limit: 100 }, { headers: evolutionHeaders });
        let mensagens = [];
        
        if (Array.isArray(response.data)) {
            mensagens = response.data;
        } else if (response.data && typeof response.data === 'object') {
            mensagens = response.data.records || response.data.messages || [];
        }

        mensagens = mensagens.map(m => {
            if(m.key && m.key.id && msgsApagadas.find(ap => ap.messageId === m.key.id)) m.zeusApagada = true;
            return m;
        });
        res.json({ sucesso: true, mensagens });
    } catch (error) { 
        res.json({ sucesso: false, mensagens: [] }); 
    }
});

// Envio Totalmente Seguro (Nunca crasheia e envia o 'composing' nativamente)
app.post('/api/chat/enviar-mensagem', verificarToken, async (req, res) => {
    const { instancia, remoteJid, texto } = req.body;
    const numLimpo = remoteJid.split('@')[0];
    
    try {
        await axios.post(`${API_URL}/message/sendText/${instancia}`, { 
            number: numLimpo, 
            options: { presence: "composing" },
            textMessage: { text: texto } 
        }, { headers: evolutionHeaders });
        
        // Retornamos um objeto simples para NÃO serializar buffers brutos de response.data
        res.json({ sucesso: true });
    } catch (error) { 
        res.json({ sucesso: false, erro: error.response?.data?.message || "Falha na API." }); 
    }
});

app.post('/api/chat/enviar-media', verificarToken, upload.single('arquivo'), async (req, res) => {
    const { instancia, remoteJid, legenda } = req.body; 
    const file = req.file; 
    if (!file) return res.json({ sucesso: false, erro: "Nenhum arquivo anexado." });
    
    const numLimpo = remoteJid.split('@')[0];
    let mt = 'document'; 
    if(file.mimetype.includes('image')) mt = 'image'; 
    if(file.mimetype.includes('video')) mt = 'video';
    
    try { 
        await axios.post(`${API_URL}/message/sendMedia/${instancia}`, { 
            number: numLimpo, 
            options: { presence: "composing" }, 
            mediaMessage: { mediatype: mt, fileName: file.originalname, caption: legenda || "", media: file.buffer.toString('base64') } 
        }, { headers: evolutionHeaders }); 
        
        res.json({ sucesso: true }); 
    } catch (e) { 
        res.json({ sucesso: false, erro: "Falha no envio da mídia." }); 
    }
});

app.post('/api/chat/enviar-audio', verificarToken, upload.single('audio'), async (req, res) => {
    const { instancia, remoteJid } = req.body;
    const numLimpo = remoteJid.split('@')[0];
    
    try { 
        await axios.post(`${API_URL}/message/sendWhatsAppAudio/${instancia}`, { 
            number: numLimpo, 
            options: { presence: "recording" }, 
            audioMessage: { audio: req.file.buffer.toString('base64') } 
        }, { headers: evolutionHeaders }); 
        
        res.json({ sucesso: true });
    } catch (e) { 
        res.json({ sucesso: false, erro: "Falha ao enviar áudio." }); 
    }
});

app.post('/api/chat/apagar-mensagem', verificarToken, async (req, res) => {
    const { instancia, remoteJid, messageId } = req.body;
    try { 
        await axios.delete(`${API_URL}/chat/deleteMessage/${instancia}`, { headers: evolutionHeaders, data: { number: remoteJid.split('@')[0], messageId: messageId, fromMe: true } }); 
        msgsApagadas.push({ messageId: messageId, data: new Date().toISOString() }); 
        salvarDados(AUDIT_FILE, msgsApagadas); 
        res.json({ sucesso: true }); 
    } catch (e) { 
        res.json({ sucesso: false, erro: "Falha ao apagar." }); 
    }
});

// ==========================================================
// CENTRAL DE CAMPANHAS ASSÍNCRONAS (ANTI-BAN)
// ==========================================================
app.get('/api/campanhas', verificarToken, (req, res) => { 
    res.json({ sucesso: true, campanhas: campanhas.filter(c => c.usuario === req.userContext.user) }); 
});

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function processarCampanhaEmSegundoPlano(campanhaId) {
    const camp = campanhas.find(x => x.id === campanhaId); 
    if(!camp) return; 
    
    camp.status = 'Em Processamento'; 
    salvarDados(CAMPAIGNS_FILE, campanhas);

    for (let i = 0; i < camp.listaContatos.length; i++) {
        let raw = camp.listaContatos[i]; 
        let num = formatarNumeroBrasil(raw);

        if(!num || num.length < 12) { 
            camp.detalhes.erros.push({ numero: raw, motivo: 'Estrutura Inválida' }); 
            camp.processados++; 
            camp.progresso = Math.round((camp.processados/camp.totalContatos)*100); 
            salvarDados(CAMPAIGNS_FILE, campanhas); 
            continue; 
        }

        let erroDetectado = false; 
        let motivoErro = '';

        for (let msg of camp.sequencia) {
            let delayHumano = Math.floor(Math.random() * (4000 - 2000 + 1)) + 2000;
            try { 
                await sleep(delayHumano);
                
                if (msg.tipo === 'texto') { 
                    let textoFinal = msg.texto.replace(/\{([^{}]+)\}/g, (m, p) => { 
                        let a = p.split('|'); 
                        return a[Math.floor(Math.random() * a.length)]; 
                    }); 
                    await axios.post(`${API_URL}/message/sendText/${camp.remetente}`, { number: num, options: { presence: "composing" }, textMessage: { text: textoFinal } }, { headers: evolutionHeaders }); 
                } else { 
                    await axios.post(`${API_URL}/message/sendMedia/${camp.remetente}`, { 
                        number: num, 
                        options: { presence: "composing" },
                        mediaMessage: { mediatype: msg.mimeType.includes('image') ? 'image' : 'document', fileName: msg.fileName, caption: msg.legenda || "", media: msg.base64.split(',')[1] } 
                    }, { headers: evolutionHeaders }); 
                }
            } catch(e) { 
                erroDetectado = true; 
                motivoErro = e.response?.data?.message || e.message; 
                break; 
            } 
            await sleep(1500);
        }

        if (erroDetectado) { 
            if (motivoErro.toLowerCase().includes('exists') || motivoErro.toLowerCase().includes('not registered')) {
                camp.detalhes.semWhats.push({ numero: num, motivo: 'Sem WhatsApp' }); 
            } else {
                camp.detalhes.erros.push({ numero: num, motivo: motivoErro }); 
            }
        } else {
            camp.detalhes.sucessos.push({ numero: num }); 
        }

        camp.processados++; 
        camp.progresso = Math.round((camp.processados / camp.totalContatos) * 100); 
        salvarDados(CAMPAIGNS_FILE, campanhas);

        if (i < camp.listaContatos.length - 1) {
            let delayFila = Math.floor(Math.random() * (25000 - 15000 + 1)) + 15000;
            await sleep(delayFila);
        }
    } 
    camp.status = 'Concluída'; 
    salvarDados(CAMPAIGNS_FILE, campanhas);
}

app.post('/api/campanhas/criar-manual', verificarToken, (req, res) => {
    let lst = req.body.numeros.split(',').map(n => n.trim()).filter(n => n);
    let novaCampanha = { 
        id: 'c_' + Date.now(), 
        usuario: req.userContext.user, 
        nome: req.body.nome, 
        remetente: req.body.remetente, 
        totalContatos: lst.length, 
        processados: 0, 
        progresso: 0, 
        status: 'Aguardando', 
        listaContatos: lst, 
        sequencia: req.body.sequencia, 
        data: new Date().toLocaleDateString('pt-BR'), 
        detalhes: { sucessos: [], semWhats: [], erros: [] } 
    };
    campanhas.push(novaCampanha); 
    salvarDados(CAMPAIGNS_FILE, campanhas); 
    processarCampanhaEmSegundoPlano(novaCampanha.id); 
    res.json({ sucesso: true });
});

app.post('/api/campanhas/criar-planilha', verificarToken, upload.single('planilha'), (req, res) => {
    let sheet = xlsx.read(req.file.buffer, { type: 'buffer' }).Sheets[xlsx.read(req.file.buffer, { type: 'buffer' }).SheetNames[0]];
    let dados = xlsx.utils.sheet_to_json(sheet, { header: 1 }); 
    let lst = []; 
    for(let i = 1; i < dados.length; i++) { 
        if (dados[i][0]) lst.push(dados[i][0]); 
    }
    let novaCampanha = { 
        id: 'c_' + Date.now(), 
        usuario: req.userContext.user, 
        nome: req.body.nome, 
        remetente: req.body.remetente, 
        totalContatos: lst.length, 
        processados: 0, 
        progresso: 0, 
        status: 'Aguardando', 
        listaContatos: lst, 
        sequencia: JSON.parse(req.body.sequencia), 
        data: new Date().toLocaleDateString('pt-BR'), 
        detalhes: { sucessos: [], semWhats: [], erros: [] } 
    };
    campanhas.push(novaCampanha); 
    salvarDados(CAMPAIGNS_FILE, campanhas); 
    processarCampanhaEmSegundoPlano(novaCampanha.id); 
    res.json({ sucesso: true });
});

// ==========================================================
// EMISSÃO DE RELATÓRIOS AVANÇADOS (EXCEL / PDF)
// ==========================================================
app.get('/api/campanhas/:id/excel', verificarToken, (req, res) => {
    const c = campanhas.find(x => x.id === req.params.id); 
    if(!c) return res.status(404).send('Inexistente.'); 
    
    const wb = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet([["Telefone"], ...c.detalhes.sucessos.map(n => [n.numero])]), "Sucessos");
    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet([["Telefone","Status"], ...c.detalhes.semWhats.map(n => [n.numero,'Sem WA'])]), "Sem WA");
    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet([["Telefone","Erro do Servidor"], ...c.detalhes.erros.map(n => [n.numero, n.motivo])]), "Erros");
    
    res.setHeader('Content-Disposition', `attachment; filename=rel_${c.nome}.xlsx`); 
    res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
});

app.get('/api/campanhas/:id/pdf', verificarToken, (req, res) => {
    const c = campanhas.find(x => x.id === req.params.id); 
    if (!c) return res.status(404).send('Inexistente.'); 
    
    const d = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Disposition', `attachment; filename=rel_${c.nome}.pdf`); 
    d.pipe(res);
    
    d.fillColor('#075e54').fontSize(22).text('ZEUS-LITE - RELATÓRIO DA CAMPANHA', { align: 'center' }).moveDown(); 
    d.fillColor('#333').fontSize(12).text(`Campanha: ${c.nome}`).text(`Data: ${c.data}`).moveDown();
    d.fillColor('#23a55a').text(`Sucessos: ${c.detalhes.sucessos.length}`)
     .fillColor('#f85149').text(`Erros: ${c.detalhes.erros.length}`)
     .fillColor('#58a6ff').text(`Sem WA: ${c.detalhes.semWhats.length}`).moveDown();
     
    c.detalhes.semWhats.forEach(i => d.fillColor('#58a6ff').text(`[Sem WA] Num: ${i.numero}`)); 
    c.detalhes.erros.forEach(i => d.fillColor('#f85149').text(`[Erro] Num: ${i.numero} - ${i.motivo}`)); 
    
    d.end();
});

app.get('/api/planilha-modelo', (req, res) => {
    const wb = xlsx.utils.book_new(); 
    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet([["Telefone"], ["41999999999"], ["5551988888888"]]), "Modelo");
    res.setHeader('Content-Disposition', 'attachment; filename=modelo_zeus_lite.xlsx'); 
    res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Zeus-Lite ativo na 3000`));