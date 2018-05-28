FROM python
RUN apt-get update &&\
      apt-get install -y git

RUN git clone https://github.com/cryptoaustralia/dingoes.git &&\
    cd dingoes
WORKDIR dingoes
RUN pip install -r requirements.txt
