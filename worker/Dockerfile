FROM eclipse-temurin:21-jre-noble

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-pip build-essential curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:/opt/jadx/bin:/usr/local/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.txt

ARG JADX_VERSION=1.5.7
ARG JADX_SHA256=1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3
RUN curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip && \
    echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c - && mkdir -p /opt/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && rm /tmp/jadx.zip

ARG APKTOOL_VERSION=3.0.3
ARG APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
RUN curl -fsSL "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" -o /opt/apktool.jar && \
    echo "${APKTOOL_SHA256}  /opt/apktool.jar" | sha256sum -c - && \
    printf '#!/bin/sh\nexec java -jar /opt/apktool.jar "$@"\n' > /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool

ARG BUNDLETOOL_VERSION=1.18.3
ARG BUNDLETOOL_SHA256=a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29
RUN curl -fsSL "https://github.com/google/bundletool/releases/download/${BUNDLETOOL_VERSION}/bundletool-all-${BUNDLETOOL_VERSION}.jar" -o /opt/bundletool.jar && \
    echo "${BUNDLETOOL_SHA256}  /opt/bundletool.jar" | sha256sum -c -

RUN useradd --system --uid 10001 --create-home worker && mkdir -p /workspace /tmp/reverselens && \
    chown -R 10001:10001 /workspace /tmp/reverselens /opt/venv
WORKDIR /app
COPY reverselens_worker ./reverselens_worker
USER 10001:10001
CMD ["python", "-m", "reverselens_worker.worker"]
