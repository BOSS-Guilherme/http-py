import sys
import threading
import time
import ctypes
from ctypes import wintypes
from datetime import datetime

import psutil

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw, conf

from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QLabel,
    QPushButton,
    QLineEdit,
    QSplitter,
    QHeaderView,
    QDialog,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QFrame
)


class Sinais(QObject):
    pacote = Signal(dict)


sinais = Sinais()


def obter_apps_abertos():
    apps = {}

    user32 = ctypes.windll.user32
    user32.EnumWindows.argtypes = [
        ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM),
        wintypes.LPARAM
    ]

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def callback(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True

        tamanho = user32.GetWindowTextLengthW(hwnd)

        if tamanho <= 0:
            return True

        titulo = ctypes.create_unicode_buffer(tamanho + 1)
        user32.GetWindowTextW(hwnd, titulo, tamanho + 1)

        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

        if pid.value == 0:
            return True

        try:
            processo = psutil.Process(pid.value)
            nome = processo.name()

            if pid.value not in apps:
                apps[pid.value] = {
                    "pid": pid.value,
                    "nome": nome,
                    "titulo": titulo.value
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return True

    user32.EnumWindows(callback, 0)

    return sorted(
        apps.values(),
        key=lambda x: x["nome"].lower()
    )


def obter_arvore_processos(pid):
    pids = {pid}

    try:
        processo = psutil.Process(pid)
        for filho in processo.children(recursive=True):
            pids.add(filho.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return pids


class MapeadorProcessos:
    def __init__(self):
        self.lock = threading.Lock()
        self.mapa_tcp = {}
        self.mapa_udp = {}
        self.pids = set()
        self.rodando = False
        self.thread = None

    def selecionar(self, pid):
        with self.lock:
            self.pids = obter_arvore_processos(pid)

    def iniciar(self):
        if self.rodando:
            return

        self.rodando = True
        self.thread = threading.Thread(
            target=self.atualizar,
            daemon=True
        )
        self.thread.start()

    def parar(self):
        self.rodando = False

    def atualizar(self):
        while self.rodando:
            tcp = {}
            udp = {}

            try:
                conexoes = psutil.net_connections(kind="inet")

                with self.lock:
                    pids = set(self.pids)

                for conexao in conexoes:
                    if conexao.pid is None or conexao.pid not in pids:
                        continue

                    if not conexao.laddr:
                        continue

                    ip_local = conexao.laddr.ip
                    porta_local = conexao.laddr.port

                    if conexao.type == 1:
                        tcp[(ip_local, porta_local)] = conexao.pid
                        tcp[("*", porta_local)] = conexao.pid
                    elif conexao.type == 2:
                        udp[(ip_local, porta_local)] = conexao.pid
                        udp[("*", porta_local)] = conexao.pid

            except (psutil.AccessDenied, psutil.Error):
                pass

            with self.lock:
                self.mapa_tcp = tcp
                self.mapa_udp = udp

            time.sleep(0.5)

    def pertence(self, p):
        if TCP not in p and UDP not in p:
            return False

        if IP in p:
            ip_origem = p[IP].src
            ip_destino = p[IP].dst
        elif IPv6 in p:
            ip_origem = p[IPv6].src
            ip_destino = p[IPv6].dst
        else:
            return False

        if TCP in p:
            porta_origem = int(p[TCP].sport)
            porta_destino = int(p[TCP].dport)

            with self.lock:
                mapa = dict(self.mapa_tcp)

        else:
            porta_origem = int(p[UDP].sport)
            porta_destino = int(p[UDP].dport)

            with self.lock:
                mapa = dict(self.mapa_udp)

        chaves = [
            (ip_origem, porta_origem),
            (ip_destino, porta_destino),
            ("*", porta_origem),
            ("*", porta_destino)
        ]

        with self.lock:
            pids = set(self.pids)

        return any(mapa.get(chave) in pids for chave in chaves)


def analisar_pacote(p):
    info = {
        "hora": datetime.now().strftime("%H:%M:%S"),
        "protocolo": "OTHER",
        "origem": "-",
        "destino": "-",
        "porta_origem": "-",
        "porta_destino": "-",
        "tamanho": len(p),
        "resumo": p.summary(),
        "payload": ""
    }

    if IP in p:
        info["origem"] = p[IP].src
        info["destino"] = p[IP].dst
    elif IPv6 in p:
        info["origem"] = p[IPv6].src
        info["destino"] = p[IPv6].dst

    if TCP in p:
        info["protocolo"] = "TCP"
        info["porta_origem"] = p[TCP].sport
        info["porta_destino"] = p[TCP].dport

        if p[TCP].dport == 443 or p[TCP].sport == 443:
            info["protocolo"] = "HTTPS"
        elif p[TCP].dport == 80 or p[TCP].sport == 80:
            info["protocolo"] = "HTTP"

    elif UDP in p:
        info["protocolo"] = "UDP"
        info["porta_origem"] = p[UDP].sport
        info["porta_destino"] = p[UDP].dport

        if DNS in p:
            info["protocolo"] = "DNS"

            try:
                if DNSQR in p:
                    info["resumo"] = f"DNS → {p[DNSQR].qname.decode(errors='ignore')}"
            except Exception:
                pass

    elif ICMP in p:
        info["protocolo"] = "ICMP"

    if Raw in p:
        raw = bytes(p[Raw].load)

        try:
            info["payload"] = raw.decode(
                "utf-8",
                errors="replace"
            )[:5000]
        except Exception:
            info["payload"] = repr(raw[:5000])

    return info


class Capturador:
    def __init__(self, interface, mapeador):
        self.interface = interface
        self.mapeador = mapeador
        self.rodando = False
        self.thread = None

    def iniciar(self):
        if self.rodando:
            return

        self.rodando = True
        self.mapeador.iniciar()

        self.thread = threading.Thread(
            target=self.capturar,
            daemon=True
        )
        self.thread.start()

    def capturar(self):
        try:
            while self.rodando:
                sniff(
                    iface=self.interface,
                    prn=self.processar,
                    store=False,
                    timeout=1
                )
        except Exception as e:
            sinais.pacote.emit({
                "erro": str(e)
            })

    def processar(self, p):
        if not self.rodando:
            return

        if self.mapeador.pertence(p):
            sinais.pacote.emit(analisar_pacote(p))

    def parar(self):
        self.rodando = False
        self.mapeador.parar()


class SeletorAplicativo(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app_selecionado = None

        self.setWindowTitle("Selecionar aplicativo")
        self.resize(700, 500)

        layout = QVBoxLayout(self)

        titulo = QLabel("APLICATIVOS ABERTOS")
        titulo.setObjectName("dialogTitulo")
        layout.addWidget(titulo)

        self.lista = QListWidget()
        layout.addWidget(self.lista)

        botoes = QHBoxLayout()

        atualizar = QPushButton("↻ ATUALIZAR")
        atualizar.clicked.connect(self.carregar_apps)

        selecionar = QPushButton("SELECIONAR")
        selecionar.clicked.connect(self.selecionar)

        cancelar = QPushButton("CANCELAR")
        cancelar.clicked.connect(self.reject)

        botoes.addWidget(atualizar)
        botoes.addStretch()
        botoes.addWidget(cancelar)
        botoes.addWidget(selecionar)

        layout.addLayout(botoes)

        self.lista.itemDoubleClicked.connect(
            lambda _: self.selecionar()
        )

        self.carregar_apps()

        self.setStyleSheet("""
            QDialog {
                background: #0b0f14;
            }

            QWidget {
                color: #d7dde5;
                font-family: "Segoe UI";
                font-size: 13px;
            }

            QLabel#dialogTitulo {
                color: #ffffff;
                font-size: 18px;
                font-weight: 700;
                padding-bottom: 8px;
            }

            QListWidget {
                background: #0f151c;
                border: 1px solid #202b38;
                border-radius: 8px;
                color: #d8e0e8;
                font-family: "Consolas";
                font-size: 12px;
                padding: 5px;
            }

            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #18212b;
            }

            QListWidget::item:selected {
                background: #20364b;
                color: #ffffff;
            }

            QPushButton {
                background: #1d2937;
                border: 1px solid #2e4054;
                border-radius: 7px;
                padding: 9px 15px;
                color: #ffffff;
                font-weight: 700;
            }

            QPushButton:hover {
                background: #26384b;
            }
        """)

    def carregar_apps(self):
        self.lista.clear()

        apps = obter_apps_abertos()

        for app in apps:
            texto = f'{app["nome"]}    PID {app["pid"]}    {app["titulo"]}'
            item = QListWidgetItem(texto)
            item.setData(
                Qt.ItemDataRole.UserRole,
                app
            )
            self.lista.addItem(item)

    def selecionar(self):
        item = self.lista.currentItem()

        if not item:
            return

        self.app_selecionado = item.data(
            Qt.ItemDataRole.UserRole
        )

        self.accept()


class Janela(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("HTTP PY")
        self.resize(1450, 850)

        self.total_pacotes = 0
        self.total_bytes = 0
        self.capturador = None
        self.app_selecionado = None
        self.mapeador = MapeadorProcessos()

        self.configurar_interface()

        sinais.pacote.connect(
            self.receber_pacote
        )

    def configurar_interface(self):
        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        topo = QHBoxLayout()
        topo.setSpacing(10)

        titulo = QLabel("HTTP PY")
        titulo.setObjectName("titulo")

        subtitulo = QLabel("NETWORK INSPECTOR")
        subtitulo.setObjectName("subtitulo")

        topo.addWidget(titulo)
        topo.addWidget(subtitulo)
        topo.addStretch()

        status_frame = QFrame()
        status_frame.setObjectName("statusFrame")

        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(12, 6, 12, 6)

        self.status = QLabel("● PARADO")
        self.status.setObjectName("status")

        status_layout.addWidget(self.status)
        topo.addWidget(status_frame)

        self.app_label = QLabel("Nenhum aplicativo selecionado")
        self.app_label.setObjectName("appLabel")
        self.app_label.setMinimumWidth(260)

        topo.addWidget(self.app_label)

        self.selecionar_app = QPushButton("▣  SELECIONAR APP")
        self.selecionar_app.clicked.connect(
            self.abrir_seletor
        )

        topo.addWidget(self.selecionar_app)

        self.botao = QPushButton("▶  INICIAR")
        self.botao.setObjectName("botaoIniciar")
        self.botao.clicked.connect(
            self.alternar_captura
        )

        topo.addWidget(self.botao)

        layout.addLayout(topo)

        barra = QHBoxLayout()
        barra.setSpacing(10)

        self.filtro = QLineEdit()
        self.filtro.setPlaceholderText(
            "Pesquisar IP, domínio, porta, protocolo..."
        )

        self.filtro.textChanged.connect(
            self.aplicar_filtro
        )

        barra.addWidget(self.filtro)

        self.contador = QLabel("0 pacotes")
        self.contador.setObjectName("contador")
        barra.addWidget(self.contador)

        self.bytes_label = QLabel("0 B")
        self.bytes_label.setObjectName("contador")
        barra.addWidget(self.bytes_label)

        layout.addLayout(barra)

        splitter = QSplitter(
            Qt.Orientation.Vertical
        )

        self.tabela = QTableWidget()
        self.tabela.setColumnCount(7)

        self.tabela.setHorizontalHeaderLabels([
            "TIME",
            "PROTOCOL",
            "SOURCE",
            "DESTINATION",
            "PORT",
            "SIZE",
            "INFORMATION"
        ])

        self.tabela.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.tabela.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )

        self.tabela.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.tabela.setAlternatingRowColors(True)
        self.tabela.verticalHeader().setVisible(False)
        self.tabela.setShowGrid(False)

        header = self.tabela.horizontalHeader()

        header.setSectionResizeMode(
            0,
            QHeaderView.ResizeMode.ResizeToContents
        )

        header.setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.ResizeToContents
        )

        header.setSectionResizeMode(
            2,
            QHeaderView.ResizeMode.Interactive
        )

        header.setSectionResizeMode(
            3,
            QHeaderView.ResizeMode.Interactive
        )

        header.setSectionResizeMode(
            4,
            QHeaderView.ResizeMode.ResizeToContents
        )

        header.setSectionResizeMode(
            5,
            QHeaderView.ResizeMode.ResizeToContents
        )

        header.setSectionResizeMode(
            6,
            QHeaderView.ResizeMode.Stretch
        )

        self.tabela.setColumnWidth(2, 190)
        self.tabela.setColumnWidth(3, 190)

        self.tabela.itemSelectionChanged.connect(
            self.mostrar_detalhes
        )

        splitter.addWidget(self.tabela)

        painel = QWidget()
        painel_layout = QVBoxLayout(painel)
        painel_layout.setContentsMargins(
            14,
            12,
            14,
            12
        )

        detalhe_topo = QHBoxLayout()

        detalhe_titulo = QLabel("PACKET DETAILS")
        detalhe_titulo.setObjectName("detalheTitulo")

        detalhe_topo.addWidget(detalhe_titulo)
        detalhe_topo.addStretch()

        painel_layout.addLayout(detalhe_topo)

        self.detalhes = QTextEdit()
        self.detalhes.setReadOnly(True)
        self.detalhes.setPlaceholderText(
            "Selecione um pacote para visualizar os detalhes."
        )

        painel_layout.addWidget(self.detalhes)

        splitter.addWidget(painel)

        splitter.setSizes([
            570,
            230
        ])

        layout.addWidget(splitter)

        self.rodape = QLabel(
            "Selecione um aplicativo para começar."
        )

        self.rodape.setObjectName("rodape")
        layout.addWidget(self.rodape)

        self.setStyleSheet("""
            QMainWindow {
                background: #0b0f14;
            }

            QWidget {
                color: #d7dde5;
                font-family: "Segoe UI";
                font-size: 13px;
            }

            QLabel#titulo {
                color: #ffffff;
                font-size: 25px;
                font-weight: 700;
            }

            QLabel#subtitulo {
                color: #687585;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 1px;
                margin-left: 4px;
            }

            QLabel#appLabel {
                background: #111720;
                border: 1px solid #263241;
                border-radius: 7px;
                padding: 9px 12px;
                color: #aeb9c6;
                font-weight: 600;
            }

            QFrame#statusFrame {
                background: #121923;
                border: 1px solid #202b38;
                border-radius: 7px;
            }

            QLabel#status {
                color: #62d98b;
                font-weight: 700;
                font-size: 12px;
            }

            QPushButton {
                background: #1d2937;
                border: 1px solid #2e4054;
                border-radius: 7px;
                padding: 9px 15px;
                color: #ffffff;
                font-weight: 700;
            }

            QPushButton:hover {
                background: #26384b;
            }

            QPushButton:pressed {
                background: #16212d;
            }

            QLineEdit {
                background: #111720;
                border: 1px solid #263241;
                border-radius: 7px;
                padding: 10px 13px;
                color: #e8edf3;
                selection-background-color: #35506b;
            }

            QLineEdit:focus {
                border: 1px solid #46627f;
            }

            QLabel#contador {
                background: #111720;
                border: 1px solid #202b38;
                border-radius: 7px;
                padding: 9px 13px;
                color: #8f9cab;
                font-weight: 600;
            }

            QTableWidget {
                background: #0f151c;
                alternate-background-color: #111923;
                border: 1px solid #202b38;
                border-radius: 8px;
                outline: none;
                font-family: "Consolas";
                font-size: 12px;
                color: #d8e0e8;
            }

            QTableWidget::item {
                padding: 8px 7px;
                border-bottom: 1px solid #18212b;
            }

            QTableWidget::item:selected {
                background: #20364b;
                color: #ffffff;
            }

            QTableWidget::item:hover {
                background: #182633;
            }

            QHeaderView::section {
                background: #151d27;
                color: #8290a0;
                border: none;
                border-bottom: 1px solid #273341;
                padding: 10px 8px;
                font-size: 11px;
                font-weight: 700;
            }

            QTextEdit {
                background: #0d131a;
                border: 1px solid #202b38;
                border-radius: 7px;
                color: #cdd6e0;
                font-family: "Consolas";
                font-size: 12px;
                padding: 8px;
            }

            QLabel#detalheTitulo {
                color: #ffffff;
                font-size: 13px;
                font-weight: 700;
            }

            QLabel#rodape {
                color: #596777;
                font-size: 11px;
                padding-left: 3px;
            }

            QSplitter::handle {
                background: #202b38;
                height: 2px;
            }

            QScrollBar:vertical {
                background: #0b0f14;
                width: 10px;
                margin: 2px;
            }

            QScrollBar::handle:vertical {
                background: #2a3745;
                border-radius: 5px;
                min-height: 30px;
            }

            QScrollBar::handle:vertical:hover {
                background: #3a4b5e;
            }

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

    def abrir_seletor(self):
        if self.capturador and self.capturador.rodando:
            QMessageBox.information(
                self,
                "Captura em andamento",
                "Pare a captura antes de selecionar outro aplicativo."
            )
            return

        dialogo = SeletorAplicativo(self)

        if dialogo.exec() != QDialog.DialogCode.Accepted:
            return

        app = dialogo.app_selecionado

        if not app:
            return

        self.app_selecionado = app

        nome = app["nome"]
        pid = app["pid"]

        self.app_label.setText(
            f"{nome}  |  PID {pid}"
        )

        self.rodape.setText(
            f"Aplicativo selecionado: {nome} (PID {pid})"
        )

    def alternar_captura(self):
        if self.capturador is None or not self.capturador.rodando:
            if not self.app_selecionado:
                QMessageBox.warning(
                    self,
                    "Nenhum aplicativo",
                    "Selecione um aplicativo antes de iniciar a captura."
                )
                return

            interface = str(conf.iface)

            self.total_pacotes = 0
            self.total_bytes = 0

            self.contador.setText("0 pacotes")
            self.bytes_label.setText("0 B")
            self.tabela.setRowCount(0)
            self.detalhes.clear()

            pid = self.app_selecionado["pid"]

            self.mapeador = MapeadorProcessos()
            self.mapeador.selecionar(pid)

            self.capturador = Capturador(
                interface,
                self.mapeador
            )

            self.capturador.iniciar()

            self.botao.setText("■  PARAR")
            self.status.setText("● CAPTURANDO")

            self.rodape.setText(
                f"Capturando {self.app_selecionado['nome']} e processos filhos"
            )

        else:
            self.capturador.parar()

            self.botao.setText("▶  INICIAR")
            self.status.setText("● PARADO")

            self.rodape.setText(
                "Captura parada"
            )

    def receber_pacote(self, info):
        if "erro" in info:
            self.detalhes.setPlainText(
                "CAPTURE ERROR\n\n" + info["erro"]
            )
            self.status.setText("● ERRO")
            return

        self.total_pacotes += 1
        self.total_bytes += info["tamanho"]

        self.contador.setText(
            f"{self.total_pacotes:,} pacotes"
        )

        self.bytes_label.setText(
            self.formatar_bytes(self.total_bytes)
        )

        linha = self.tabela.rowCount()

        self.tabela.insertRow(linha)

        valores = [
            info["hora"],
            info["protocolo"],
            info["origem"],
            info["destino"],
            f'{info["porta_origem"]} → {info["porta_destino"]}',
            self.formatar_bytes(info["tamanho"]),
            info["resumo"]
        ]

        for coluna, valor in enumerate(valores):
            item = QTableWidgetItem(str(valor))
            self.tabela.setItem(
                linha,
                coluna,
                item
            )

        self.tabela.item(
            linha,
            0
        ).setData(
            Qt.ItemDataRole.UserRole,
            info
        )

        if self.tabela.rowCount() > 2000:
            self.tabela.removeRow(0)

        self.tabela.scrollToBottom()
        self.aplicar_filtro()

    def aplicar_filtro(self):
        texto = self.filtro.text().lower().strip()

        for linha in range(self.tabela.rowCount()):
            if not texto:
                self.tabela.setRowHidden(
                    linha,
                    False
                )
                continue

            valores = []

            for coluna in range(self.tabela.columnCount()):
                item = self.tabela.item(
                    linha,
                    coluna
                )

                if item:
                    valores.append(item.text().lower())

            encontrado = texto in " ".join(valores)

            self.tabela.setRowHidden(
                linha,
                not encontrado
            )

    def mostrar_detalhes(self):
        linhas = (
            self.tabela
            .selectionModel()
            .selectedRows()
        )

        if not linhas:
            return

        linha = linhas[0].row()

        item = self.tabela.item(
            linha,
            0
        )

        if not item:
            return

        info = item.data(
            Qt.ItemDataRole.UserRole
        )

        if not info:
            return

        texto = f"""
TIME
{info["hora"]}

PROTOCOL
{info["protocolo"]}

SOURCE
{info["origem"]}:{info["porta_origem"]}

DESTINATION
{info["destino"]}:{info["porta_destino"]}

SIZE
{self.formatar_bytes(info["tamanho"])}

SUMMARY
{info["resumo"]}

PAYLOAD
{info["payload"]}
"""

        self.detalhes.setPlainText(
            texto.strip()
        )

    @staticmethod
    def formatar_bytes(valor):
        if valor < 1024:
            return f"{valor} B"

        if valor < 1024 ** 2:
            return f"{valor / 1024:.1f} KB"

        if valor < 1024 ** 3:
            return f"{valor / 1024 ** 2:.1f} MB"

        return f"{valor / 1024 ** 3:.2f} GB"


if __name__ == "__main__":
    app = QApplication(sys.argv)

    janela = Janela()
    janela.show()

    sys.exit(
        app.exec()
    )