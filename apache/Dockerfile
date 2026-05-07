FROM php:8.2-apache

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        libcap2-bin \
        default-mysql-client \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install mysqli pdo pdo_mysql

RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump || true

# 한글 인코딩: Apache 응답 기본 charset 을 UTF-8 로 강제
RUN echo "AddDefaultCharset UTF-8" >> /etc/apache2/apache2.conf

COPY www/ /var/www/html/
COPY tcpdump.sh /usr/local/bin/tcpdump.sh
COPY delay.sh /usr/local/bin/delay.sh
RUN chmod +x /usr/local/bin/tcpdump.sh /usr/local/bin/delay.sh && \
    mkdir -p /pcap && chmod 777 /pcap

EXPOSE 80

CMD ["/usr/local/bin/delay.sh"]
