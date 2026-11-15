# HTTP PY

Olá! Eu sou **Guilherme**, desenvolvedor do **HTTP PY**.

O HTTP PY nasceu durante meus estudos sobre **análise e monitoramento de tráfego de rede**, com o objetivo de aprender, na prática, como dados trafegam entre aplicações e redes.

Após concluir meus estudos e ficar satisfeito com o resultado alcançado, decidi compartilhar o projeto publicamente para que outras pessoas também possam conhecer, estudar e experimentar a ferramenta.

Posteriormente, solicitei o auxílio de uma IA para finalizar o projeto, implementar novos recursos e desenvolver uma interface gráfica mais completa. Por esse motivo, o projeto pode apresentar alguns bugs ou comportamentos inesperados. Mesmo assim, o resultado final se tornou uma ferramenta bastante poderosa para **captura, análise e monitoramento de tráfego de rede**.

## O que é o HTTP PY?

O HTTP PY é uma ferramenta desenvolvida em Python para **capturar e analisar pacotes de rede em tempo real**, permitindo visualizar informações sobre o tráfego que está sendo transmitido pelo computador.

Um dos principais recursos do projeto é a possibilidade de selecionar uma aplicação em execução no Windows e tentar identificar o tráfego de rede relacionado a ela.

A ferramenta apresenta as informações capturadas através de uma interface gráfica, facilitando a visualização e análise dos pacotes.

## Como a ferramenta funciona?

O funcionamento do HTTP PY envolve diferentes componentes trabalhando em conjunto:

### 1. Captura dos pacotes

O projeto utiliza **Scapy** para realizar a captura e análise dos pacotes de rede.

O Scapy permite que o HTTP PY observe o tráfego que passa pelas interfaces de rede e extraia informações dos pacotes capturados.

### 2. Npcap

No Windows, o projeto utiliza o **Npcap** como camada de captura de rede.

O Npcap permite que aplicações tenham acesso aos pacotes que trafegam pelas interfaces de rede do sistema.

Por isso, o Npcap é necessário para que a captura de pacotes funcione corretamente no Windows.

### 3. Identificação das aplicações

O HTTP PY utiliza o **psutil** para consultar as conexões de rede existentes no sistema e relacioná-las aos processos responsáveis por essas conexões.

Dessa forma, a ferramenta consegue tentar determinar qual aplicação está relacionada a determinado tráfego.

O projeto também identifica processos filhos de uma aplicação, aumentando a possibilidade de encontrar corretamente o tráfego gerado por programas que utilizam múltiplos processos.

### 4. Interface gráfica

A interface foi desenvolvida utilizando **PySide6**, permitindo que o usuário visualize as informações capturadas de maneira organizada.

A interface apresenta recursos como:

* Seleção de aplicações em execução;
* Captura de tráfego em tempo real;
* Lista de pacotes capturados;
* Informações sobre protocolos;
* Endereços IP de origem e destino;
* Portas de comunicação;
* Tamanho dos pacotes;
* Filtros;
* Visualização de detalhes dos pacotes;
* Controle para iniciar e interromper a captura.

## Principais tecnologias

O projeto utiliza principalmente:

* **Python** — linguagem principal do projeto;
* **Scapy** — captura e análise de pacotes;
* **PySide6** — desenvolvimento da interface gráfica;
* **psutil** — identificação de processos e conexões de rede;
* **Npcap** — captura de pacotes no Windows.

## Dependências

Para executar o projeto, são necessárias as seguintes dependências Python:

```text
scapy
PySide6
psutil
```

Além das bibliotecas Python, no Windows é necessário instalar o **Npcap**, pois ele fornece a infraestrutura necessária para a captura dos pacotes de rede.

As dependências Python podem ser instaladas utilizando:

```bash
pip install scapy PySide6 psutil
```

## Limitações

O HTTP PY foi desenvolvido principalmente como um projeto de **estudo e aprendizado**, portanto sua identificação de processos e captura de tráfego funciona de maneira best-effort.

Aplicações que utilizam múltiplos processos, serviços auxiliares ou determinados mecanismos de comunicação podem apresentar situações em que o tráfego não seja associado corretamente ao processo esperado.

Outro ponto importante é que o projeto **não descriptografa automaticamente HTTPS**. Quando uma aplicação utiliza HTTPS, o conteúdo da comunicação normalmente permanece criptografado, embora informações dos pacotes, como IPs, portas, protocolos e tamanho dos dados, ainda possam ser analisadas.

Executar a ferramenta com privilégios de **Administrador** no Windows também pode melhorar a capacidade de visualização de determinadas conexões.

## Objetivo do projeto

O principal objetivo do HTTP PY é servir como uma ferramenta de **estudo, experimentação e análise de tráfego de rede**.

O projeto também pode servir como base para futuros recursos, melhorias de interface, novos filtros, análise mais avançada de protocolos e outras funcionalidades relacionadas ao monitoramento de redes.

Este projeto foi publicado principalmente para compartilhar o resultado dos meus estudos e permitir que outras pessoas possam utilizá-lo, estudá-lo e contribuir com sua evolução.

> **Aviso:** utilize o HTTP PY somente em redes, computadores e aplicações que você tenha autorização para monitorar. O projeto é destinado a fins educacionais, de desenvolvimento e análise autorizada.
