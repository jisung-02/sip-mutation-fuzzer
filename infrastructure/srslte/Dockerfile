# Based on herlesupreeth/docker_open5gs/srslte/Dockerfile
FROM ubuntu:jammy

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libfftw3-dev \
    libmbedtls-dev \
    libboost-program-options-dev \
    libboost-thread-dev \
    libconfig++-dev \
    libsctp-dev \
    libzmq3-dev \
    libusb-1.0-0-dev \
    libcurl4-openssl-dev \
    libncurses-dev \
    libedit-dev \
    net-tools \
    iputils-ping \
    iproute2 \
    iptables \
    git \
    tcpdump \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# UHD (USRP)
RUN apt-get update && apt-get install -y libuhd-dev uhd-host \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV UHD_IMAGES_DIR=/usr/share/uhd/images/

RUN /usr/lib/uhd/utils/uhd_images_downloader.py || true

# SoapySDR
RUN git clone https://github.com/pothosware/SoapySDR.git && \
    cd SoapySDR && \
    git checkout soapy-sdr-0.8.1 && \
    mkdir build && cd build && \
    cmake ../ && make && make install && \
    ldconfig && \
    cd ../.. && rm -rf SoapySDR

# LimeSuite
RUN git clone https://github.com/myriadrf/LimeSuite.git && \
    cd LimeSuite && \
    mkdir builddir && cd builddir && \
    cmake ../ && make && make install && \
    ldconfig && \
    cd ../.. && rm -rf LimeSuite

# BladeRF
RUN git clone https://github.com/Nuand/bladeRF.git && \
    cd bladeRF/host && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DINSTALL_UDEV_RULES=ON \
          ../ && \
    make && make install && \
    ldconfig && \
    cd ../../.. && rm -rf bladeRF

# SoapyBladeRF
RUN git clone https://github.com/pothosware/SoapyBladeRF.git && \
    cd SoapyBladeRF && \
    mkdir build && cd build && \
    cmake ../ && make && make install && \
    ldconfig && \
    cd ../.. && rm -rf SoapyBladeRF

# srsRAN 4G
RUN git clone https://github.com/srsran/srsRAN_4G.git && \
    cd srsRAN_4G && \
    git checkout release_23_11 && \
    mkdir build && cd build && \
    cmake ../ && make -j$(nproc) && make install && \
    ldconfig && \
    srsran_install_configs.sh service && \
    cd ../.. && rm -rf srsRAN_4G

WORKDIR /mnt/srslte

ENTRYPOINT ["/mnt/srslte/srslte_init.sh"]
