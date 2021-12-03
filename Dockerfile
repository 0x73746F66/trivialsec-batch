FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/scheduler"

ARG COMMON_VERSION
ARG BUILD_ENV
ARG GITLAB_USER
ARG GITLAB_PASSWORD

ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /srv/app
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV LOG_LEVEL ${LOG_LEVEL}
ENV TZ="Australia/Sydney"

WORKDIR /srv/app
USER root
COPY conf/crontab /etc/cron.d/trivialsec
RUN mkdir -p /var/log/trivialsec /var/cache/trivialsec \
    && chown -R trivialsec:trivialsec /var/log/trivialsec /var/cache/trivialsec \
    && echo "Installing System Packages" \
    && apt-get -q update \
    && apt-get -qy install cron \
    && chmod 600 /etc/cron.d/trivialsec \
    && echo "Clean up..." \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /tmp/* /var/lib/apt/lists/*

USER trivialsec
RUN python3 -m pip install -q --no-cache-dir --no-warn-script-location -U pip 2>/dev/null \
    && echo "Cloning Python Libs Package from Gitlab" \
    && git clone -q -c advice.detachedHead=false --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/python-libs \
    && cd /tmp/python-libs \
    && echo "Installing Packages" \
    && make install \
    && cd /srv/app \
    && echo "Clean up..." \
    && rm -rf /tmp/python-libs \
# forward request and error logs to docker log collector
    && touch /var/log/trivialsec/cron.log \
    && touch /var/log/trivialsec/cron-error.log \
    && ln -sf /dev/stdout /var/log/trivialsec/cron.log \
    && ln -sf /dev/stderr /var/log/trivialsec/cron-error.log

COPY --chown=trivialsec:trivialsec *.env .
COPY --chown=trivialsec:trivialsec src src
COPY --chown=trivialsec:trivialsec requirements.txt requirements.txt
RUN pip install --user -r requirements.txt
USER root
CMD ["cron", "-f", "-l", "8"]