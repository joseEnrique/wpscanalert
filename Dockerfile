FROM ubuntu:16.04

RUN apt update && apt install -y python python-pip git libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev gem &&  \
    GIT_CURLOPT_SSLVERSION=3 && git clone https://github.com/wpscanteam/wpscan.git && cd wpscan && gem install bundler && bundle install --without test \
     && rm -rf /var/lib/apt/lists/*


ENV WPSCAN_DIR=/wpscan

WORKDIR /wpscanalert

COPY ./ .

RUN pip install -r requirements.txt

CMD python wpscanalert.py