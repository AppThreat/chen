FROM ghcr.io/appthreat/base:main

LABEL maintainer="appthreat" \
      org.opencontainers.image.authors="Team AppThreat <cloud@appthreat.com>" \
      org.opencontainers.image.source="https://github.com/appthreat/chen" \
      org.opencontainers.image.url="https://github.com/appthreat/chen" \
      org.opencontainers.image.version="2.4.x" \
      org.opencontainers.image.vendor="appthreat" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="chen" \
      org.opencontainers.image.description="Container image for AppThreat chen code analysis platform" \
      org.opencontainers.docker.cmd="docker run --rm -v /tmp:/tmp -v $HOME:$HOME -v $(pwd):/app:rw -it ghcr.io/appthreat/chen chennai"

ARG JAVA_VERSION=23.0.2-tem
ARG MAVEN_VERSION=3.9.10
ARG GRADLE_VERSION=8.13
ARG RUBY_VERSION=3.4.4
ARG SCALA_VERSION=3.6.4

ENV JAVA_VERSION=$JAVA_VERSION \
    MAVEN_VERSION=$MAVEN_VERSION \
    GRADLE_VERSION=$GRADLE_VERSION \
    RUBY_VERSION=$RUBY_VERSION \
    SCALA_VERSION=$SCALA_VERSION \
    SCALA_HOME="/opt/scala/${SCALA_VERSION}" \
    GRADLE_OPTS="-Dorg.gradle.daemon=false" \
    JAVA_HOME="/opt/java/${JAVA_VERSION}" \
    MAVEN_HOME="/opt/maven/${MAVEN_VERSION}" \
    GRADLE_HOME="/opt/gradle/${GRADLE_VERSION}" \
    PYTHON_CMD=python3 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8" \
    JAVA_OPTS="-XX:+UseG1GC -XX:+ExplicitGCInvokesConcurrent -XX:+ParallelRefProcEnabled -XX:+UseStringDeduplication -XX:+UnlockExperimentalVMOptions -XX:G1NewSizePercent=20 -XX:+UnlockDiagnosticVMOptions -XX:G1SummarizeRSetStatsPeriod=1 -Dorg.jline.terminal.disableDeprecatedProviderWarning=true" \
    CHEN_DATAFLOW_TRACKED_WIDTH=128 \
    SCALAPY_PYTHON_LIBRARY=python3.12 \
    ANDROID_HOME=/opt/android-sdk-linux \
    CHEN_INSTALL_DIR=/opt/workspace \
    PHP_PARSER_BIN=/opt/vendor/bin/php-parse \
    CDXGEN_NO_BANNER=true \
    COMPOSER_ALLOW_SUPERUSER=1 \
    MALLOC_CONF="dirty_decay_ms:2000,narenas:2,background_thread:true" \
    RUBY_CONFIGURE_OPTS="--with-jemalloc --enable-yjit" \
    RUBYOPT="--yjit" \
    RUBY_BUILD_BUILD_PATH="/tmp/rbenv" \
    RUBY_BUILD_HTTP_CLIENT=curl
ENV PATH=/opt/miniconda3/bin:${PATH}:/opt/platform:${JAVA_HOME}/bin:${MAVEN_HOME}/bin:${SCALA_HOME}/bin:${GRADLE_HOME}/bin:/usr/local/bin/:/root/.local/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/tools:${ANDROID_HOME}/tools/bin:${ANDROID_HOME}/platform-tools:/root/.rbenv/bin:/root/.rbenv/versions/${RUBY_VERSION}/bin:

WORKDIR /opt
COPY ./ci/conda-install.sh /opt/
COPY README.md /opt/
COPY ./platform/frontends/php2atom/composer.json /opt/composer.json
COPY ./platform/frontends/php2atom/composer.json /opt/composer.lock

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
    && microdnf install -y gcc git-core php php-cli php-curl php-zip php-bcmath php-json php-pear php-mbstring php-devel make wget bash graphviz graphviz-gd \
        openssl-devel libffi-devel readline-devel libyaml zlib-devel ncurses ncurses-devel rust \
        pcre2 findutils which tar gzip zip unzip sudo nodejs sqlite-devel glibc-common glibc-all-langpacks \
    && microdnf install -y epel-release \
    && microdnf install --enablerepo=crb -y libyaml-devel jemalloc-devel \
    && git clone https://github.com/rbenv/rbenv.git --depth=1 ~/.rbenv \
    && echo 'export PATH="/root/.rbenv/bin:$PATH"' >> ~/.bashrc \
    && echo 'eval "$(/root/.rbenv/bin/rbenv init - bash)"' >> ~/.bashrc \
    && source ~/.bashrc \
    && mkdir -p "$(rbenv root)/plugins" \
    && git clone https://github.com/rbenv/ruby-build.git --depth=1 "$(rbenv root)/plugins/ruby-build" \
    && rbenv install ${RUBY_VERSION} -- --disable-install-doc \
    && rbenv global ${RUBY_VERSION} \
    && ruby --version \
    && which ruby \
    && rm -rf /root/.rbenv/cache $RUBY_BUILD_BUILD_PATH \
    && mkdir -p /opt/miniconda3 /opt/workspace \
    && wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-${ARCH_NAME}.sh -O /opt/miniconda3/miniconda.sh \
    && bash /opt/miniconda3/miniconda.sh -b -u -p /opt/miniconda3 \
    && rm -rf /opt/miniconda3/miniconda.sh \
    && ln -s /opt/miniconda3/etc/profile.d/conda.sh /etc/profile.d/conda.sh \
    && echo ". /opt/miniconda3/etc/profile.d/conda.sh" >> ~/.bashrc \
    && conda install python=3.12 -y \
    && conda config --set solver classic \
    && conda update -n base -c defaults conda -y \
    && conda config --add channels conda-forge \
    && conda init bash \
    && bash -c /opt/conda-install.sh \
    && curl -LO https://repo.almalinux.org/almalinux/9/CRB/${ARCH_NAME}/os/Packages/graphviz-devel-2.44.0-26.el9.${ARCH_NAME}.rpm \
    && rpm -ivh graphviz-devel-2.44.0-26.el9.${ARCH_NAME}.rpm \
    && rm graphviz-devel-2.44.0-26.el9.${ARCH_NAME}.rpm \
    && curl -s "https://get.sdkman.io" | bash \
    && source "/root/.sdkman/bin/sdkman-init.sh" \
    && echo -e "sdkman_auto_answer=true\nsdkman_selfupdate_feature=false\nsdkman_auto_env=true\nsdkman_curl_connect_timeout=20\nsdkman_curl_max_time=0" >> /root/.sdkman/etc/config \
    && sdk install java $JAVA_VERSION \
    && sdk install maven $MAVEN_VERSION \
    && sdk install gradle $GRADLE_VERSION \
    && sdk install scala $SCALA_VERSION \
    && sdk offline enable \
    && mv /root/.sdkman/candidates/* /opt/ \
    && rm -rf /root/.sdkman \
    && mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -L https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && unzip ${ANDROID_HOME}/cmdline-tools/android_tools.zip -d ${ANDROID_HOME}/cmdline-tools/ \
    && rm ${ANDROID_HOME}/cmdline-tools/android_tools.zip \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && yes | /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager --licenses --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platform-tools' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'platforms;android-34' --sdk_root=/opt/android-sdk-linux \
    && /opt/android-sdk-linux/cmdline-tools/latest/bin/sdkmanager 'build-tools;34.0.0' --sdk_root=/opt/android-sdk-linux \
    && npm install -g @appthreat/atom @cyclonedx/cdxgen --omit=optional \
    && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && php composer-setup.php \
    && mv composer.phar /usr/local/bin/composer
ENV LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8 -Djna.library.path=/opt/miniconda3/lib"
COPY ./chenpy /opt/chenpy
COPY ./pyproject.toml /opt/
COPY ./target/chen.zip .
COPY ./notebooks /opt/notebooks
RUN unzip -q chen.zip \
    && composer update --no-progress --prefer-dist --ignore-platform-reqs \
    && python -m pip install --no-deps . \
    && rm chen.zip conda-install.sh pyproject.toml \
    && microdnf clean all
CMD ["chennai"]
