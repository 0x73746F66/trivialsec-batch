FROM docker.io/library/python:3.9-slim
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/batch"

ARG TRIVIALSEC_PY_LIB_VER
ARG CRONICLE_VERSION
ARG GITLAB_USER
ARG GITLAB_PASSWORD
ARG TZ "Australia/Sydney"

ENV DEBIAN_FRONTEND noninteractive
ENV NODE_VERSION 16.13.1
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV LOG_LEVEL ${LOG_LEVEL}
ENV EDITOR nano
ENV CRONICLE_echo 1
ENV CRONICLE_foreground 1
ENV PATH="$PATH:/srv/app/.local/bin"
 ADD source dest
RUN echo "Preparing folders..." && \
    mkdir -p /var/log/trivialsec /var/cache/trivialsec /opt/cronicle && \
    echo "Creating user and group..." && \
    addgroup trivialsec && \
    adduser --disabled-password --gecos '' --disabled-login --home /srv/app --ingroup trivialsec trivialsec && \
    chown -R trivialsec:trivialsec /var/log/trivialsec /var/cache/trivialsec && \
    echo "Set timezone ${TZ}..." && \
    ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo ${TZ} | tee /etc/timezone && dpkg-reconfigure tzdata && \
    echo "Patching..." && \
    apt-get -q update && \
    apt-get upgrade -qy && \
    echo "Installing Dependencies..." && \
    apt-get -qy install --no-install-recommends \
        build-essential tzdata git bash rsyslog procps curl xz-utils nano \
        ca-certificates openssl python3-dev default-mysql-client nodejs npm && \
    echo "Clean up..." && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /tmp/* /var/lib/apt/lists/*

WORKDIR /srv/app
USER trivialsec
RUN python3 -m pip install -q -U --no-warn-script-location pip && \
    echo "Cloning Python Libs Package from Gitlab" && \
    git clone -q -c advice.detachedHead=false --depth 1 --branch ${TRIVIALSEC_PY_LIB_VER} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/python-libs && \
    cd /tmp/python-libs && \
    echo "Installing Packages" && \
    make install

COPY --chown=trivialsec:trivialsec *.env .
COPY --chown=trivialsec:trivialsec src src
COPY --chown=trivialsec:trivialsec requirements.txt requirements.txt
RUN pip install --user --no-warn-script-location -r requirements.txt

USER root
WORKDIR /opt/cronicle
COPY conf/cronicle/config.json conf/config.json
COPY conf/cronicle/setup.json conf/setup.json
RUN echo "Installing Cronicle v${CRONICLE_VERSION}..." \
    && curl -sL https://github.com/jhuckaby/Cronicle/archive/v${CRONICLE_VERSION}.tar.gz | tar zxvf - --strip-components 1 \
    && npm install \
    && node bin/build.js dist \
    && bin/control.sh setup \
    && echo "Clean up..." \
    && rm -rf /tmp/*

WORKDIR /srv/app
CMD ["node", "/opt/cronicle/lib/main.js"]
