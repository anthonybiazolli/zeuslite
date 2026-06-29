// server.js
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
app.set('trust proxy', true);

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
const HEALTH_FILE = path.join(__dirname, 'saude_numeros.json');

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
        twoFactorConfigured: false,
        status: 'ativo',
        termosAceitos: true
    }
]);
let campanhas = carregarDados(CAMPAIGNS_FILE, []);
let msgsApagadas = carregarDados(AUDIT_FILE, []);
let saudeNumeros = carregarDados(HEALTH_FILE, {});

function registrarSaude(instancia, metrica, valor = 1) {
    if (!saudeNumeros[instancia]) {
        saudeNumeros[instancia] = {
            score: 100, // 100-80: Verde, 79-50: Amarelo, <50: Vermelho
            dataPrimeiraConexao: new Date().toISOString(),
            qtdCampanhas: 0,
            novasConversasIniciadas: 0,
            mensagensEnviadas: 0,
            mensagensEntregues: 0,
            mensagensLidas: 0,
            conversasRespondidas: 0,
            mensagensNaoChegaram: 0
        };
    }
    
    saudeNumeros[instancia][metrica] += valor;
    
    // Atualiza o Score Baseado nas interações
    if(metrica === 'mensagensEnviadas') saudeNumeros[instancia].score -= 0.1;
    if(metrica === 'mensagensEntregues') saudeNumeros[instancia].score += 0.05;
    if(metrica === 'mensagensLidas') saudeNumeros[instancia].score += 0.1;
    if(metrica === 'conversasRespondidas') saudeNumeros[instancia].score += 1.0;
    if(metrica === 'mensagensNaoChegaram') saudeNumeros[instancia].score -= 0.5;

    if(saudeNumeros[instancia].score > 100) saudeNumeros[instancia].score = 100;
    if(saudeNumeros[instancia].score < 0) saudeNumeros[instancia].score = 0;

    salvarDados(HEALTH_FILE, saudeNumeros);
}

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
    
    if (userFound.status === 'suspenso') {
        return res.status(403).json({ sucesso: false, erro: 'Sua conta foi suspensa pela administração.' });
    }

    if (!userFound.termosAceitos) {
        return res.json({ sucesso: true, requerTermos: true, user: userFound.usuario });
    }

    if (userFound.deveAlterarSenha) return res.json({ sucesso: true, requerTrocaSenha: true, user: userFound.usuario });

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

app.post('/api/usuarios/aceitar-termos', (req, res) => {
    const { usuario, regiao } = req.body;
    const userFound = usuarios.find(u => u.usuario === usuario);
    if (!userFound) return res.status(404).json({ erro: 'Usuário não encontrado.' });

    userFound.termosAceitos = true;
    userFound.termosDetalhes = {
        ip: req.ip || req.connection.remoteAddress,
        regiao: regiao,
        dataHora: new Date().toISOString()
    };
    
    salvarDados(USERS_FILE, usuarios);

    if (userFound.deveAlterarSenha) return res.json({ sucesso: true, requerTrocaSenha: true, user: userFound.usuario });
    if (userFound.role === 'admin' && !userFound.twoFactorConfigured) return res.json({ sucesso: true, requer2FA: true, user: userFound.usuario });

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

    if (userFound.role === 'admin' && !userFound.twoFactorConfigured) return res.json({ sucesso: true, requer2FA: true, user: userFound.usuario });

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
        deveAlterarSenha: true, status: 'ativo', termosAceitos: false 
    });
    salvarDados(USERS_FILE, usuarios);
    res.json({ sucesso: true });
});

app.post('/api/admin/usuarios/:id/status', verificarToken, (req, res) => {
    if (req.userContext.role !== 'admin') return res.status(403).json({ erro: 'Negado.' });
    const u = usuarios.find(x => x.usuario === req.params.id);
    if(u) { u.status = req.body.status; salvarDados(USERS_FILE, usuarios); }
    res.json({ sucesso: true });
});

app.post('/api/admin/usuarios/:id/deletar', verificarToken, (req, res) => {
    if (req.userContext.role !== 'admin') return res.status(403).json({ erro: 'Negado.' });
    usuarios = usuarios.filter(x => x.usuario !== req.params.id);
    salvarDados(USERS_FILE, usuarios);
    res.json({ sucesso: true });
});

app.post('/api/admin/usuarios/:id/reset-senha', verificarToken, (req, res) => {
    if (req.userContext.role !== 'admin') return res.status(403).json({ erro: 'Negado.' });
    const u = usuarios.find(x => x.usuario === req.params.id);
    if(u) { 
        u.senha = 'Zeus@' + Math.floor(Math.random() * 9999);
        u.deveAlterarSenha = true; 
        salvarDados(USERS_FILE, usuarios); 
        res.json({ sucesso: true, novaSenhaTemp: u.senha });
    } else {
        res.json({ sucesso: false, erro: 'Usuário não encontrado' });
    }
});

app.post('/api/admin/usuarios/:id/editar', verificarToken, (req, res) => {
    if (req.userContext.role !== 'admin') return res.status(403).json({ erro: 'Negado.' });
    const idx = usuarios.findIndex(x => x.usuario === req.params.id);
    if(idx !== -1) { 
        usuarios[idx] = { ...usuarios[idx], ...req.body };
        salvarDados(USERS_FILE, usuarios); 
        res.json({ sucesso: true });
    } else {
        res.json({ sucesso: false, erro: 'Usuário não encontrado' });
    }
});

// ==========================================================
// GESTÃO DE INSTÂNCIAS (QR / PIN) E SAÚDE
// ==========================================================
app.get('/api/instancias', verificarToken, async (req, res) => {
    try {
        const response = await axios.get(`${API_URL}/instance/fetchInstances`, { headers: evolutionHeaders });
        const list = Array.isArray(response.data) ? response.data : [];
        const prefixoDono = req.userContext.user;

        const filtradas = list.filter(item => item.instance.instanceName.startsWith(prefixoDono)).map(item => {
            let idExibicao = item.instance.instanceName.split('-')[1] || item.instance.instanceName.replace(prefixoDono, '');
            if(!saudeNumeros[item.instance.instanceName]) registrarSaude(item.instance.instanceName, 'qtdCampanhas', 0);
            return {
                nome: item.instance.instanceName,
                idExibicao: idExibicao.toUpperCase(),
                status: item.instance.status,
                numero: item.instance.owner ? item.instance.owner.replace('@s.whatsapp.net', '') : 'Aguardando Sincronização',
                saude: saudeNumeros[item.instance.instanceName] || {}
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
        registrarSaude(nomeCompletoInstancia, 'qtdCampanhas', 0);
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
        if(pinCode) {
            registrarSaude(nomeCompletoInstancia, 'qtdCampanhas', 0);
            res.json({ sucesso: true, pairingCode: pinCode, idGerado: novoIdMaiusculo });
        }
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

// WEBHOOK SIMULADO PARA ATUALIZAR SAUDE (Em produção apontar evolution para esta rota)
app.post('/api/webhook/evolution', (req, res) => {
    const { instance, event, data } = req.body;
    if(event === 'messages.upsert' && !data.key.fromMe) {
        registrarSaude(instance, 'conversasRespondidas');
    }
    if(event === 'messages.update') {
        if(data.status === 'DELIVERY_ACK') registrarSaude(instance, 'mensagensEntregues');
        if(data.status === 'READ') registrarSaude(instance, 'mensagensLidas');
    }
    res.sendStatus(200);
});

// ==========================================================
// CENTRAL DE CAMPANHAS ASSÍNCRONAS (ANTI-BAN)
// ==========================================================
app.get('/api/campanhas', verificarToken, (req, res) => { 
    res.json({ sucesso: true, campanhas: campanhas.filter(c => c.usuario === req.userContext.user) }); 
});

app.post('/api/campanhas/:id/status', verificarToken, (req, res) => {
    const { status } = req.body;
    const c = campanhas.find(x => x.id === req.params.id && x.usuario === req.userContext.user);
    if(c) {
        if (c.status === 'Concluída') return res.json({ sucesso: false, erro: 'Campanha já finalizada.'});
        c.status = status;
        salvarDados(CAMPAIGNS_FILE, campanhas);
        res.json({ sucesso: true });
    } else {
        res.json({ sucesso: false, erro: 'Campanha não encontrada.' });
    }
});

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function processarCampanhaEmSegundoPlano(campanhaId) {
    const camp = campanhas.find(x => x.id === campanhaId); 
    if(!camp) return; 
    
    camp.status = 'Em Processamento'; 
    salvarDados(CAMPAIGNS_FILE, campanhas);
    registrarSaude(camp.remetente, 'qtdCampanhas', 1);

    for (let i = camp.processados; i < camp.listaContatos.length; i++) {
        
        while(camp.status === 'Suspensa') {
            await sleep(3000);
            if(!campanhas.find(x => x.id === campanhaId)) return;
        }

        if(camp.status === 'Cancelada') {
            salvarDados(CAMPAIGNS_FILE, campanhas);
            return;
        }

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

        registrarSaude(camp.remetente, 'novasConversasIniciadas');

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
                registrarSaude(camp.remetente, 'mensagensEnviadas');
            } catch(e) { 
                erroDetectado = true; 
                motivoErro = e.response?.data?.message || e.message; 
                registrarSaude(camp.remetente, 'mensagensNaoChegaram');
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

        if (i < camp.listaContatos.length - 1 && camp.status === 'Em Processamento') {
            let delayFila = Math.floor(Math.random() * (25000 - 15000 + 1)) + 15000;
            await sleep(delayFila);
        }
    } 
    
    if(camp.status !== 'Cancelada') camp.status = 'Concluída'; 
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
    
    // Status Geral da Campanha
    let statusData = [
        ["Nome da Campanha", c.nome],
        ["Data", c.data],
        ["Status", c.status],
        ["Total Contatos", c.totalContatos],
        ["Processados", c.processados],
        ["Faltantes", c.totalContatos - c.processados]
    ];
    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(statusData), "Resumo");

    // Copia das Mensagens e Mídias
    let seqData = [["Tipo", "Conteúdo/Legenda", "Arquivo"]];
    c.sequencia.forEach(s => {
        if(s.tipo === 'texto') seqData.push(['Texto', s.texto, 'N/A']);
        else seqData.push(['Mídia', s.legenda || 'N/A', s.fileName]);
    });
    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(seqData), "Conteudo da Campanha");

    // Relacao de Contatos
    let contatosData = [["Telefone", "Status Envios", "Detalhe Erro"]];
    c.detalhes.sucessos.forEach(s => contatosData.push([s.numero, 'Sucesso', '']));
    c.detalhes.semWhats.forEach(s => contatosData.push([s.numero, 'Sem WhatsApp', '']));
    c.detalhes.erros.forEach(s => contatosData.push([s.numero, 'Erro', s.motivo]));
    
    // Nao processados
    const processadosAteAgora = [...c.detalhes.sucessos, ...c.detalhes.semWhats, ...c.detalhes.erros].map(x => x.numero);
    c.listaContatos.forEach(numRaw => {
        let n = formatarNumeroBrasil(numRaw);
        if(!processadosAteAgora.includes(n)) {
            contatosData.push([n, 'Na Fila / Não Enviado', '']);
        }
    });

    xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(contatosData), "Relação Completa");
    
    res.setHeader('Content-Disposition', `attachment; filename=rel_${c.nome}.xlsx`); 
    res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
});

app.get('/api/saude/:instancia/relatorio', verificarToken, (req, res) => {
    const inst = req.params.instancia;
    if(!inst.startsWith(req.userContext.user)) return res.status(403).send('Negado');
    const saude = saudeNumeros[inst] || null;
    if(!saude) return res.status(404).send('Dados não encontrados.');

    const d = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Disposition', `attachment; filename=saude_${inst}.pdf`); 
    d.pipe(res);

    d.fillColor('#075e54').fontSize(22).text('ZEUS-LITE - SAÚDE DO NÚMERO', { align: 'center' }).moveDown(); 
    d.fillColor('#333').fontSize(12).text(`Número/Instância: ${inst.split('-')[1].toUpperCase()}`).moveDown();
    
    d.text(`Data da Primeira Conexão: ${new Date(saude.dataPrimeiraConexao).toLocaleString()}`);
    d.text(`Total de Campanhas Executadas: ${saude.qtdCampanhas}`);
    d.text(`Novas Conversas Iniciadas: ${saude.novasConversasIniciadas}`);
    d.text(`Mensagens Enviadas (Total): ${saude.mensagensEnviadas}`);
    d.text(`Mensagens Entregues (Chegaram): ${saude.mensagensEntregues}`);
    d.text(`Mensagens Lidas: ${saude.mensagensLidas}`);
    d.text(`Conversas Respondidas Após Envio: ${saude.conversasRespondidas}`);
    d.text(`Mensagens Bloqueadas/Não Chegaram: ${saude.mensagensNaoChegaram}`);
    
    d.moveDown().fontSize(16).text(`Score de Saúde Meta: ${saude.score.toFixed(2)} / 100`, { align: 'center' });
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