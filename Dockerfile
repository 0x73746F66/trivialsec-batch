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

WORKDIR /srv/app
USER root
RUN mkdir -p /var/log/trivialsec /var/cache/trivialsec
USER trivialsec
COPY --chown=trivialsec:trivialsec conf/crontab scheduler
COPY --chown=trivialsec:trivialsec bin/entrypoint /entrypoint
RUN python3 -m pip install -q --no-cache-dir --no-warn-script-location -U pip 2>/dev/null \
    && echo "Cloning Python Libs Package from Gitlab" \
    && git clone -q -c advice.detachedHead=false --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/python-libs \
    && cd /tmp/python-libs \
    && echo "Installing Packages" \
    && make install \
    && cd /srv/app \
    && echo "Clean up..." \
    && rm -rf /tmp/python-libs

COPY --chown=trivialsec:trivialsec src src
COPY --chown=trivialsec:trivialsec requirements.txt requirements.txt
RUN pip install -q --user -r requirements.txt

ENTRYPOINT ["/entrypoint"]
CMD ["crond", "-f", "-l", "8"]
