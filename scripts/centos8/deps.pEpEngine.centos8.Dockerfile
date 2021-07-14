ARG DOCKER_REGISTRY_HOST
ARG CURRENT_DISTRO
ARG PEPENGINE_VERSION
ARG SEQUOIA_VERSION
FROM ${DOCKER_REGISTRY_HOST}/pep-${CURRENT_DISTRO}-sequoia:${SEQUOIA_VERSION}

ENV BUILDROOT /build
ENV INSTPREFIX /install
ENV OUTDIR /out
ARG PEP_MACHINE_DIR

### Setup working directory
RUN mkdir ${BUILDROOT}/pEpEngine
COPY ./scripts/common/build_pEpEngine_deps.sh ${BUILDROOT}/pEpEngine

USER root

RUN yum install -y python3 python3-lxml binutils && yum clean all

RUN chown -R pep-builder:pep-builder ${BUILDROOT}/pEpEngine
WORKDIR ${BUILDROOT}/pEpEngine

ARG YML2_VERSION
ARG ENGINE_VERSION
ARG CURRENT_DISTRO

### Build pEpEngine dependencies
USER pep-builder

RUN sh ./build_pEpEngine_deps.sh
