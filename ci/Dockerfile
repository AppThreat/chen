FROM almalinux:9.2-minimal

LABEL maintainer="appthreat" \
      org.opencontainers.image.authors="Team AppThreat <cloud@appthreat.com>" \
      org.opencontainers.image.source="https://github.com/appthreat/chen" \
      org.opencontainers.image.url="https://github.com/appthreat/chen" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="appthreat" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="chen" \
      org.opencontainers.image.description="Container image for AppThreat chen code analysis platform" \
      org.opencontainers.docker.cmd="docker run --rm -v /tmp:/tmp -v $(pwd):/app:rw -t ghcr.io/appthreat/chen chennai"

ARG JAVA_VERSION=21-graalce
ARG MAVEN_VERSION=3.9.3
ARG GRADLE_VERSION=8.2.1

ENV JAVA_VERSION=$JAVA_VERSION \
    MAVEN_VERSION=$MAVEN_VERSION \
    GRADLE_VERSION=$GRADLE_VERSION \
    GRADLE_OPTS="-Dorg.gradle.daemon=false" \
    JAVA_HOME="/opt/java/${JAVA_VERSION}" \
    MAVEN_HOME="/opt/maven/${MAVEN_VERSION}" \
    GRADLE_HOME="/opt/gradle/${GRADLE_VERSION}" \
    PYTHON_CMD=python3 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8" \
    JAVA_OPTS="-XX:+UseG1GC -XX:+ExplicitGCInvokesConcurrent -XX:+ParallelRefProcEnabled -XX:+UseStringDeduplication -XX:+UnlockExperimentalVMOptions -XX:G1NewSizePercent=20 -XX:+UnlockDiagnosticVMOptions -XX:G1SummarizeRSetStatsPeriod=1" \
    JOERN_DATAFLOW_TRACKED_WIDTH=128 \
    SCALAPY_PYTHON_LIBRARY=python3.11 \
    ANDROID_HOME=/opt/android-sdk-linux
ENV PATH=${PATH}:/opt/platform:${JAVA_HOME}/bin:${MAVEN_HOME}/bin:${GRADLE_HOME}/bin:/usr/local/bin/:/root/.local/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/tools:${ANDROID_HOME}/tools/bin:${ANDROID_HOME}/platform-tools:

WORKDIR /opt
COPY ./ci/requirements.txt /opt/
COPY ./ci/kernel.json /opt/
RUN set -e; \
    ARCH_NAME="$(rpm --eval '%{_arch}')"; \
    url=; \
    case "${ARCH_NAME##*-}" in \
        'x86_64') \
            OS_ARCH_SUFFIX=''; \
            GOBIN_VERSION='amd64'; \
            ;; \
        'aarch64') \
            OS_ARCH_SUFFIX='-aarch64'; \
            GOBIN_VERSION='arm64'; \
            ;; \
        *) echo >&2 "error: unsupported architecture: '$ARCH_NAME'"; exit 1 ;; \
    esac; \
    echo -e "[nodejs]\nname=nodejs\nstream=20\nprofiles=\nstate=enabled\n" > /etc/dnf/modules.d/nodejs.module \
    && microdnf install -y gcc git-core \
        python3.11 python3.11-devel python3.11-pip graphviz graphviz-gd graphviz-python3 \
        pcre2 findutils which tar gzip zip unzip sudo nodejs ncurses sqlite-devel \
    && alternatives --install /usr/bin/python3 python /usr/bin/python3.11 1 \
    && python3 --version \
    && curl -LO https://repo.almalinux.org/almalinux/9/CRB/${ARCH_NAME}/os/Packages/graphviz-devel-2.44.0-25.el9.${ARCH_NAME}.rpm \
    && rpm -ivh graphviz-devel-2.44.0-25.el9.${ARCH_NAME}.rpm \
    && rm graphviz-devel-2.44.0-25.el9.${ARCH_NAME}.rpm \
    && python3.11 -m pip install -r /opt/requirements.txt notebook owasp-depscan \
    && python3.11 -m pip install virtualenv numpy GitPython pandas graphviz pydotplus networkx[default,extra] \
    && python3.11 -m pip install torch --index-url https://download.pytorch.org/whl/cpu \
    && python3.11 -m pip install torch_geometric pyg_lib torch_scatter torch_sparse torch_cluster torch_spline_conv -f https://data.pyg.org/whl/torch-2.0.0+cpu.html \
    && curl -s "https://get.sdkman.io" | bash \
    && source "$HOME/.sdkman/bin/sdkman-init.sh" \
    && echo -e "sdkman_auto_answer=true\nsdkman_selfupdate_feature=false\nsdkman_auto_env=true" >> $HOME/.sdkman/etc/config \
    && sdk install java $JAVA_VERSION \
    && sdk install maven $MAVEN_VERSION \
    && sdk install gradle $GRADLE_VERSION \
    && sdk offline enable \
    && mv /root/.sdkman/candidates/* /opt/ \
    && rm -rf /root/.sdkman \
    && microdnf install -y epel-release \
    && mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -L https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip -o ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && unzip ${ANDROID_HOME}/cmdline-tools/android_tools.zip -d ${ANDROID_HOME}/cmdline-tools/ \
    && rm ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && yes | /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager --licenses --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platform-tools' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platforms;android-33' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'build-tools;33.0.0' --sdk_root=/opt/android-sdk-linux \
    && curl -Lo coursier https://git.io/coursier-cli \
    && chmod +x coursier \
    && ./coursier launch almond:0.14.0-RC13 --scala 3.3.0 -- --install \
    && cp /opt/kernel.json /root/.local/share/jupyter/kernels/scala/ \
    && sudo npm install -g @cyclonedx/cdxgen --omit=optional \
    && rm -f coursier
COPY ./target/chen.zip .
COPY ./notebooks /opt/notebooks
RUN unzip -q chen.zip \
    && rm chen.zip kernel.json requirements.txt \
    && microdnf clean all
ENV CLASSPATH=$CLASSPATH:/opt/platform/lib/*.jar:
CMD ["chennai"]
