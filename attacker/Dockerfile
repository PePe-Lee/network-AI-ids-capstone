FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
COPY install.sh /install.sh
COPY attack.sh /attack.sh
COPY ddos_attack.sh /ddos_attack.sh
COPY ddos_simulate.py /ddos_simulate.py
RUN chmod +x /install.sh /attack.sh /ddos_attack.sh
CMD ["bash", "/install.sh"]
